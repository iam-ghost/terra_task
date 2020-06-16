provider "aws" {
  region  = "ap-south-1"
  profile = "iamkunal"
}

#creating_security_groups
resource "aws_security_group" "firewall" {
  name        = "firewall"
  description = "Allow TLS inbound traffic"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ingress_http_ssh"
  }
}

#creating_keys
resource "tls_private_key" "infra_key" {
  algorithm = "RSA"
  rsa_bits = 4096
}
resource "aws_key_pair" "infra_key" {
  key_name   = "infra_key"
  public_key = tls_private_key.infra_key.public_key_openssh
}
resource "local_file" "infra_key" {
  content = tls_private_key.infra_key.private_key_pem
  filename = "/root/terraform/infra_key.pem"
}

#launching_instances
resource "aws_instance" "web" {
  depends_on = [
    tls_private_key.infra_key,
    aws_key_pair.infra_key,
    local_file.infra_key,
    aws_security_group.firewall,
  ]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = "infra_key"
  security_groups = [ "firewall" ]
  connection {
   type     = "ssh"
   user     = "ec2-user"
   private_key = tls_private_key.infra_key.private_key_pem
   host     = aws_instance.web.public_ip
 }

 provisioner "remote-exec" {
   inline = [
     "sudo yum install httpd  php git -y",
     "sudo systemctl restart httpd",
     "sudo systemctl enable httpd",
   ]
 }
  tags = {
    Name = "TestInfra"
   }
}

#creating_block_storage
resource "aws_ebs_volume" "web_store" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1
  encrypted = true
  tags = {
    Name = "web_ebs"
  }
}
#attaching_block_to_instance
resource "aws_volume_attachment" "ebs_att" {
  depends_on = [
    aws_instance.web,
  ]
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.web_store.id
  instance_id = aws_instance.web.id
  force_detach = true
}

#mount_storage
resource "null_resource" "mount_vol" {
  depends_on = [
    aws_volume_attachment.ebs_att,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.infra_key.private_key_pem
    host     = aws_instance.web.public_ip
   }
  provisioner "remote-exec" {
      inline = [
        "sudo mkfs.ext4  /dev/xvdh",
        "sudo mount  /dev/xvdh  /var/www/html",
        "sudo rm -rf /var/www/html/*",
        "sudo git clone https://github.com/iam-ghost/terra_task.git /var/www/html/"
        ]
      }
}


#creating S3 bucket:
resource "aws_s3_bucket" "terraimages" {
  depends_on = [
      aws_instance.web
  ]

  bucket = "terraimages"
  acl    = "public-read"
  region = "ap-south-1"
  tags = {
    Name        = "infrabucket"
    Environment = "Dev"
  }

  provisioner "local-exec" {
    command = "git clone https://github.com/iam-ghost/terra_task/ infra/ "
    }
  provisioner "local-exec" {
    when = destroy
    command = "echo Y | rmdir /s image"
    }
}

/*resource "aws_s3_bucket_public_access_block" "allow_s3_public" {
  depends_on = [
    aws_s3_bucket.terraimages,
  ]
  bucket = "terraimages"
}*/

#Documenting_policy_for_s3
data "aws_iam_policy_document" "s3_bucket_policy" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.terraimages.arn}/*"]

    principals {
      type = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }
  }

  statement {
    actions = ["s3:ListBucket"]
    resources = [aws_s3_bucket.terraimages.arn]

    principals {
      type = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }

  }
}

#creating bucket policy
resource "aws_s3_bucket_policy" "s3BucketPolicy" {
  depends_on = [
        aws_s3_bucket.terraimages,
    ]
  bucket = aws_s3_bucket.terraimages.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}

#Uploading_image_to_bucket:
resource "aws_s3_bucket_object" "objectimg" {
 depends_on = [
      aws_s3_bucket.terraimages
    ]
  bucket = "terraimages"
  key    = "1.png"
  acl    = "public-read"
  source = "infra/images/1.png"
}
  locals {
    s3_origin_id = "myS3Origin"
    }

#creating CloudFront distribution:
resource "aws_cloudfront_distribution" "s3_distribution" {
  depends_on = [
    aws_s3_bucket.terraimages,
  ]
  origin {
    domain_name = aws_s3_bucket.terraimages.bucket_domain_name
    origin_id   = local.s3_origin_id

  s3_origin_config {
    origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
  }
  }


  enabled             = true
  is_ipv6_enabled     = true

  default_cache_behavior  {
    allowed_methods  = ["GET", "HEAD" , "DELETE" , "OPTIONS" ,  "PATCH" , "POST", "PUT" ]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }


  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true



  }
}



#access_identity_for_cloudfront
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Some comment"
}
output "cloudfront-origin" {
  value = "aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path"
}


#Updating_code_with_cloudfront_domain
resource "null_resource" "portal" {
  depends_on =[ aws_cloudfront_distribution.s3_distribution,aws_instance.web,aws_volume_attachment.ebs_att ]
    connection {
      type = "ssh"
      user = "ec2-user"
      host = aws_instance.web.public_ip
      port = 22
      private_key = tls_private_key.infra_key.private_key_pem
    }

  provisioner "remote-exec" {
    inline = [
      "sudo su <<EOF",
      "echo \"<img src = 'http://${aws_cloudfront_distribution.s3_distribution.domain_name}/${aws_s3_bucket_object.objectimg.key}' style='width:128px;height:128px;'>\" >> /var/www/html/index.html",
      "EOF",
      "sudo systemctl restart httpd"
     ]
 }
}


resource "null_resource" "launch_portal"  {
  depends_on = [
    null_resource.portal,
  ]
  provisioner "local-exec" {
	    command = "chrome  ${aws_instance.web.public_ip}"
  	}
}


output "cloudfront_domain" {
  value = aws_cloudfront_distribution.s3_distribution.domain_name
}

output "bucket_id" {
  value = aws_s3_bucket.terraimages.id
}


output "aws_instance_ip" {
  value = aws_instance.web.public_ip
}
