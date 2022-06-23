
resource "aws_vpc" "vpc-first" {
  cidr_block = "10.0.0.0/16"

  tags = {

    Name = "vpc-ssm"
    
  }
}
resource "aws_internet_gateway" "gw-first" {
  vpc_id = aws_vpc.vpc-first.id

  tags = {

    Name = "vpc-second-terraform"

  }

}
resource "aws_route_table" "prod-route-table" {
  vpc_id = aws_vpc.vpc-first.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw-first.id
  }

  route {
    ipv6_cidr_block        = "::/0"
    gateway_id = aws_internet_gateway.gw-first.id
  }

  tags = {
    Name = "prod-route-table-terraform"
  }
}

resource "aws_subnet" "prod-subnet" {
  vpc_id     = aws_vpc.vpc-first.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-east-2a"
  tags = {
    Name = "vpc-terraform-subnet "
  }
}
resource "aws_route_table_association" "aa1" {
  subnet_id      = aws_subnet.prod-subnet.id
  route_table_id = aws_route_table.prod-route-table.id
}
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ITKey" {
  key_name   = "kd"
  public_key = tls_private_key.example.public_key_openssh
}

resource "aws_security_group" "allow_web" {
name        = "webserver"
vpc_id      = aws_vpc.vpc-first.id
description = "Allows access to Web Port"
#allow http 
ingress {
from_port   = 80
to_port     = 80
protocol    = "tcp"
cidr_blocks = ["0.0.0.0/0"]
}
# allow https
ingress {
from_port   = 443
to_port     = 443
protocol    = "tcp"
cidr_blocks = ["0.0.0.0/0"]
}
# allow SSH
ingress {
from_port   = 22
to_port     = 22
protocol    = "tcp"
cidr_blocks = ["0.0.0.0/0"]
}
#all outbound
egress {
from_port   = 0
to_port     = 0
protocol    = "-1"
cidr_blocks = ["0.0.0.0/0"]
}
tags = {
stack = "test"
}
lifecycle {
create_before_destroy = true
}
} #security group ends here

resource "aws_network_interface" "web-server-nic" {
  subnet_id       = aws_subnet.prod-subnet.id
  private_ips     = ["10.0.1.50"]
  security_groups = [aws_security_group.allow_web.id]

}

resource "aws_eip" "one" {
  vpc                       = true
  network_interface         = aws_network_interface.web-server-nic.id
  associate_with_private_ip = "10.0.1.50"
  depends_on                = [aws_internet_gateway.gw-first]
}

resource "aws_instance" "web-server-instance" {

  ami = "ami-0aeb7c931a5a61206"
  instance_type = "t2.micro"
  availability_zone = "us-east-2a"
#  subnet_id              = aws_subnet.prod-subnet.id
#  vpc_security_group_ids = [aws_security_group.allow_web.id]
 iam_instance_profile = aws_iam_instance_profile.dev-resources-iam-profile.name 
 key_name               = aws_key_pair.ITKey.key_name
 user_data = <<-EOF
#!/bin/bash
mkdir /tmp/ssm
cd /tmp/ssm
wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
sudo dpkg -i amazon-ssm-agent.deb
sudo start amazon-ssm-agent
sudo systemctl enable amazon-ssm-agent
EOF
root_block_device {
delete_on_termination = true
volume_type           = "gp2"
volume_size           = 20
}
tags = {
 Name                   = "test-ec2"
 owner                  = "maly@deloitte.ca"
 stack                  = "test"
 "Patch Group" = "Ubuntu-OS"
}
  network_interface {
    
    device_index = 0
    network_interface_id = aws_network_interface.web-server-nic.id

  }
}
resource "aws_iam_instance_profile" "dev-resources-iam-profile" {
name = "ec2_profile"
role = aws_iam_role.dev-resources-iam-role.name
}
resource "aws_iam_role" "dev-resources-iam-role" {
name        = "dev-ssm-role"
description = "The role for the developer resources EC2"
assume_role_policy = <<EOF
{
"Version": "2012-10-17",
"Statement": {
"Effect": "Allow",
"Principal": {"Service": "ec2.amazonaws.com"},
"Action": "sts:AssumeRole"
}
}
EOF
tags = {
stack = "test"
}
}
resource "aws_iam_role_policy_attachment" "dev-resources-ssm-policy" {
role       = aws_iam_role.dev-resources-iam-role.name
policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_ssm_patch_baseline" "Ubuntu" {
  name             = "Ubuntu-Patches"
  description      = "Patch Ubuntu OS"
  operating_system = "UBUNTU"

  approval_rule {
    approve_after_days = 7
 patch_filter {
      key    = "PRODUCT"
      values = ["Ubuntu14.04", "Ubuntu16.04", "Ubuntu18.04", "Ubuntu20.04", "Ubuntu20.10"]
    }
    patch_filter {
      key    = "PRIORITY"
      values = ["Required", "Important", "Standard"]
    }
  }

}


resource "aws_ssm_patch_group" "patchgroup" {
  baseline_id = aws_ssm_patch_baseline.Ubuntu.id
  patch_group = "Ubuntu-OS"
}

resource "aws_ssm_maintenance_window" "Ubuntu" {
  name     = "maintenance-window-application"
  schedule = "cron(40 21 ? * * *)"
  duration = 3
  cutoff   = 1
}

resource "aws_ssm_maintenance_window_target" "target-Ubuntu" {
  window_id     = aws_ssm_maintenance_window.Ubuntu.id
  name          = "maintenance-window-target"
  description   = "This is a maintenance window target for Ubuntu instances"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:Patch Group"
    values = ["Ubuntu-OS"]
  }
}
