/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- root/main_spoke_account.tf ---

# ---------- AWS ACCOUNTS ----------
data "aws_caller_identity" "aws_spoke_account" {
  provider = aws.awsspoke
}

# ---------- INGRESS VPCs ----------
module "ingress_vpcs" {
  providers = { aws = aws.awsspoke }
  for_each  = var.ingress_vpcs
  source    = "aws-ia/vpc/aws"
  version   = "= 4.2.1"

  name       = each.value.name
  cidr_block = each.value.cidr_block
  az_count   = each.value.number_azs

  transit_gateway_id = aws_ec2_transit_gateway.transit_gateway.id
  transit_gateway_routes = {
    workload = "0.0.0.0/0"
  }

  subnets = {
    public = {
      cidrs          = slice(each.value.public_subnet_cidrs, 0, each.value.number_azs)
      #connect_to_igw = false
    }
    workload        = { cidrs = slice(each.value.workload_subnet_cidrs, 0, each.value.number_azs) }
    transit_gateway = { cidrs = slice(each.value.tgw_subnet_cidrs, 0, each.value.number_azs) }
  }

  tags = {
    fms_ingress = true
  }
}

# ---------- COMPUTE (NLB + EC2 INSTANCES) ----------
# Data resource to determine the latest Amazon Linux2 AMI
data "aws_ami" "amazon_linux" {
  provider = aws.awsspoke

  most_recent = true
  owners      = ["amazon"]

  filter {
    name = "name"
    values = [
      "amzn-ami-hvm-*-x86_64-gp2",
    ]
  }

  filter {
    name = "owner-alias"
    values = [
      "amazon",
    ]
  }
}

# NLB and EC2 instances
module "compute" {
  source    = "./modules/compute"
  providers = { aws = aws.awsspoke }
  for_each  = module.ingress_vpcs

  vpc_name         = each.key
  vpc              = each.value
  vpc_cidr         = var.ingress_vpcs[each.key].cidr_block
  ami_id           = data.aws_ami.amazon_linux.id
  instance_type    = var.ingress_vpcs[each.key].instance_type
  instance_profile = aws_iam_instance_profile.ec2_instance_profile.id
}

# ---------- ROUTING TO NETWORK FIREWALL RESOURCES (CREATED BY FIREWALL MANAGER) ----------
# module "vpc_resources" {
#   providers = {
#     aws = aws.awsspoke
#   }
#   for_each = module.ingress_vpcs
#   source = "./modules/vpc-resources"

#   vpc_id = each.value.vpc_attributes.id
#   vpc_name = each.key
#   igw_id = each.value.internet_gateway[0].id
#   aws_region = var.aws_region
#   azs = each.value.azs
#   firewall_manager_information = {
#     name = "ingress-fms-policy"
#     id = aws_fms_policy.ingress_policy.id
#   }
# }

# module "vpc_routes" {
#   providers = { aws = aws.awsspoke }
#   for_each  = module.ingress_vpcs
#   source    = "./modules/vpc-routes"

#   public_subnet_route_tables   = { for k, v in each.value.rt_attributes_by_type_by_az.public : k => v.id }
#   firewall_subnet_route_tables = module.vpc_resources[each.key].firewall_route_tables
#   igw_route_table              = module.vpc_resources[each.key].igw_route_table
#   internet_gateway             = each.value.internet_gateway[0].id
#   firewall_endpoints           = module.vpc_resources[each.key].firewall_endpoints
#   public_subnet_cidrs          = var.ingress_vpcs[each.key].public_subnet_cidrs
#   azs                          = each.value.azs
# }

# ---------- IAM ROLE (AWS SYSTEMS MANAGER ACCESS) ----------
# IAM instance profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  provider = aws.awsspoke

  name = "ec2_instance_profile_${var.identifier}"
  role = aws_iam_role.role_ec2.id
}

# IAM role
resource "aws_iam_role" "role_ec2" {
  provider = aws.awsspoke

  name               = "ec2_ssm_role_${var.identifier}"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.policy_document.json
}

data "aws_iam_policy_document" "policy_document" {
  statement {
    sid     = "1"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

  }
}

# Policies Attachment to Role
resource "aws_iam_policy_attachment" "ssm_iam_role_policy_attachment" {
  provider = aws.awsspoke

  name       = "ssm_iam_role_policy_attachment_${var.identifier}"
  roles      = [aws_iam_role.role_ec2.id]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}