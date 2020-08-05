# configure the provider
provider "aws" {
  region     = "ap-south-1"
  profile    = "jack" 
} 

# creating a key pair
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits = 4096
}
resource "aws_key_pair" "new_key" {
 key_name = "terra_key"
 public_key = tls_private_key.key.public_key_openssh

depends_on = [
    tls_private_key.key
]
}

# saving key to local file
resource "local_file" "foo" {
    content  = tls_private_key.key.private_key_pem
    filename = "C:/Users/user/Desktop/terra/efs/terra_key.pem"
    file_permission = "0400"
}

# creating a Security group
resource "aws_security_group" "shield" {
  name        = "shield"
  description = "Allow TLS inbound traffic" 

 ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  ingress {
    description = "HHTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
   ingress {
    description = "NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }  

  tags = {
    Name = "shield"
  }
}

# launching an ec2 instance
resource "aws_instance" "my_os" {
   depends_on = [
        aws_security_group.shield,
        tls_private_key.key,
   ]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = aws_key_pair.new_key.key_name
  security_groups = ["shield"]

 tags = {
    Name = "new_os"
  }

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = "${tls_private_key.key.private_key_pem}"
    host     = aws_instance.my_os.public_ip
  }
 
  provisioner "remote-exec" {
     inline = [
      "sudo yum install httpd php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
      "sudo yum install amazon-efs-utils -y",
      "sudo yum install nfs-utils -y", 
      
    ]
  }

}

# creating EFS 
resource "aws_efs_file_system" "My-EFS" {
 depends_on =  [ aws_security_group.shield,
                aws_instance.my_os,  ] 
  creation_token = "new-efs"

  tags = {
    Name = "My-EFS"
  }
}

# creating EFS policy
resource "aws_efs_file_system_policy" "policy" {
  depends_on = [ aws_efs_file_system.My-EFS,
   ]
  file_system_id = aws_efs_file_system.My-EFS.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-37ea40d1-826a-4398-99d6-a4561182f9f6",
    "Statement": [
        {
            "Sid": "efs-statement-65263caf-dba3-4299-b808-4da9635bba63",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Resource": "${aws_efs_file_system.allow_nfs.arn}",
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "true"
                }
            }
        }
    ]
}
POLICY
}
# Attaching EFS to EC2 
resource "aws_efs_mount_target" "allow" {
 depends_on =  [ aws_efs_file_system.My-EFS,
                 aws_efs_file_system_policy.policy,
                  ] 
  file_system_id = aws_efs_file_system.My-EFS.id
  subnet_id      = aws_instance.my_os.subnet_id
  security_groups = ["${aws_security_group.shield.id}"]
}


#configuration and mounting
resource "null_resource" "newlocal" {
   depends_on = [
         aws_efs_mount_target.allow,
         aws_efs_file_system_policy.policy,
   ]
  
    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = "${tls_private_key.key.private_key_pem}"
    host     = aws_instance.my_os.public_ip
  }
  
  provisioner "remote-exec" {
      inline = [     
              "sudo chmod ugo+rw /etc/fstab",
              "sudo echo '${aws_efs_file_system.My-EFS.id}:/ /var/www/html efs tls,_netdev' >> /etc/fstab",
              "sudo mount -a -t efs,nfs4 defaults",
              "sudo rm -rf /var/www/html/*",
              "sudo git clone https://github.com/kunal1601/AWS_EFS.git /var/www/html",
             
     ]

  }
}

output "IP_of_instance" {
  value = aws_instance.my_os.public_ip
}

#download github repo to loacl-system
resource "null_resource" "newlocal2"  {
depends_on = [ null_resource.newlocal,
             ]
    provisioner "local-exec" {
    command = "git clone https://github.com/kunal1601/AWS_EFS.git  C:/Users/user/Desktop/terra/efs/github"
   }
}

#Creating S3 bucket
resource "aws_s3_bucket" "new_bucket" {
  depends_on = [ null_resource.newlocal2 ,
               ]
  bucket = "just-relax"
  acl    = "public-read"
  
}

#Uploading file to S3 bucket
resource "aws_s3_bucket_object" "calm" {
  depends_on = [ aws_s3_bucket.new_bucket,
                 null_resource.newlocal2,
                ]

  bucket = "${aws_s3_bucket.new_bucket.id}"
  key    = "one"
  source = "C:/Users/user/Desktop/terra/efs/github/efs.png"
  acl = "public-read"
  content_type = "image/jpg"

}

resource "aws_cloudfront_origin_access_identity" "o" {
  comment = "this is OAI"
}

#Creating Cloud-front and attaching S3 bucket to it
resource "aws_cloudfront_distribution" "CDN" {
    origin {
        domain_name = aws_s3_bucket.new_bucket.bucket_domain_name
        origin_id   = "S3-just-relax"

        s3_origin_config {
           origin_access_identity = aws_cloudfront_origin_access_identity.o.cloudfront_access_identity_path
       }
    }
       
    enabled = true
    is_ipv6_enabled     = true

    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "S3-just-relax"

        forwarded_values {
            query_string = false
        
            cookies {
               forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }

    restrictions {
        geo_restriction {
            restriction_type = "none"
        }
    }

    viewer_certificate {
        cloudfront_default_certificate = true
    }
 connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = "${tls_private_key.key.private_key_pem}"
    host     = aws_instance.my_os.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo su << EOF",
      "echo \"<img src='https://${self.domain_name}/${aws_s3_bucket_object.calm.key}'>\" >> /var/www/html/index.html",
      "EOF"
    ]
  }
   depends_on = [
        aws_s3_bucket_object.calm ,
          ]
}        
 
resource "null_resource" "nulllocal1"  {
    depends_on = [  aws_cloudfront_distribution.CDN,
                  ]
provisioner "local-exec" {
          
    command = "start chrome ${aws_instance.my_os.public_ip}"
  }
}

