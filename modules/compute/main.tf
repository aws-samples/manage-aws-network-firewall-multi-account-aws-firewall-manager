/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/compute/main.tf ---



# ---------- NETWORK LOAD BALANCER ----------
# Network Load Balancer resource
resource "aws_lb" "nlb" {
  name               = "nlb-${var.vpc_name}"
  internal           = false
  load_balancer_type = "network"
  subnets            = values({ for k, v in var.vpc.public_subnet_attributes_by_az : k => v.id })
}

# Listener
resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# Target Group
resource "aws_lb_target_group" "tg" {
  name               = "tg-${var.vpc_name}"
  port               = 80
  protocol           = "TCP"
  vpc_id             = var.vpc.vpc_attributes.id
  preserve_client_ip = false
}

resource "aws_lb_target_group_attachment" "instance_attachment" {
  count = length(var.vpc.azs)

  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.ec2_instance[count.index].id
  port             = 80
}

# ---------- BACKEND INSTANCES (one per AZ) ----------
# Security Group
resource "aws_security_group" "instance_sg" {
  name        = local.instance_sg.name
  description = local.instance_sg.description
  vpc_id      = var.vpc.vpc_attributes.id

  dynamic "ingress" {
    for_each = local.instance_sg.ingress
    content {
      description = ingress.value.description
      from_port   = ingress.value.from
      to_port     = ingress.value.to
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  dynamic "egress" {
    for_each = local.instance_sg.egress
    content {
      description = egress.value.description
      from_port   = egress.value.from
      to_port     = egress.value.to
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }
}

# EC2 instances
resource "aws_instance" "ec2_instance" {
  count = length(var.vpc.azs)

  ami                         = var.ami_id
  associate_public_ip_address = false
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.instance_sg.id]
  subnet_id                   = values({ for k, v in var.vpc.private_subnet_attributes_by_az : split("/", k)[1] => v.id if split("/", k)[0] == "workload" })[count.index]
  iam_instance_profile        = var.instance_profile

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted = true
  }

  user_data = <<EOF
#!/bin/bash
sudo su
yum update -y
yum install -y httpd
service httpd start
echo "Welcome to re:Inforce 2023. This is host $(hostname -f)" > /var/www/html/index.html
service httpd restart
EOF

  tags = {
    Name = "${var.vpc_name}-instance-${count.index + 1}"
  }
}