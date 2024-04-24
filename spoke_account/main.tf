/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- spoke_account//main.tf ---

# ---------- AWS ORGANIZATIONS AND ACCOUNT INFORMATION ----------
data "aws_caller_identity" "aws_spoke_account" {}

# ---------- RETRIEVING INFORMATION FROM CENTRAL ACCOUNT (SECRETS MANAGER) ----------
# AWS Transit Gateway ID
data "aws_secretsmanager_secret" "transit_gateway" {
  arn = "arn:aws:secretsmanager:${var.aws_region}:${var.central_account_id}:secret:${var.secrets_names.transit_gateway}"
}

data "aws_secretsmanager_secret_version" "transit_gateway" {
  secret_id = data.aws_secretsmanager_secret.transit_gateway.id
}

# AWS Firewall Manager ID
data "aws_secretsmanager_secret" "firewall_manager" {
  arn = "arn:aws:secretsmanager:${var.aws_region}:${var.central_account_id}:secret:${var.secrets_names.firewall_manager}"
}

data "aws_secretsmanager_secret_version" "firewall_manager" {
  secret_id = data.aws_secretsmanager_secret.firewall_manager.id
}

# ---------- INGRESS VPCs ----------
module "ingress_vpcs" {
  for_each = var.ingress_vpcs
  source   = "aws-ia/vpc/aws"
  version  = "= 4.2.1"

  name       = each.value.name
  cidr_block = each.value.cidr_block
  az_count   = each.value.number_azs

  transit_gateway_id = data.aws_secretsmanager_secret_version.transit_gateway.secret_string
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

# ---------- SHARING VPC INFORMATION TO CENTRAL ACCOUNT ----------
# We retrieve the Secrets Manager secret created by the Central Account
data "aws_secretsmanager_secret" "spoke_vpc_information" {
  arn = "arn:aws:secretsmanager:${var.aws_region}:${var.central_account_id}:secret:${var.secrets_names.spoke_vpc_information}"
}

# We generate the secret we want to pass - with the Spoke VPCs information
locals {
  vpc_information = {
    spoke_account = {
      id                  = data.aws_caller_identity.aws_spoke_account.id
      firewall_subnet_ids = flatten(values({ for k, v in var.ingress_vpcs : k => slice(v.firewall_subnet_cidrs, 0, v.number_azs) }))
      number_spoke_vpcs   = length(var.ingress_vpcs)
      vpc_information = { for k, v in module.ingress_vpcs : k => {
        vpc_id                        = v.vpc_attributes.id
        transit_gateway_attachment_id = v.transit_gateway_attachment_id
      } }
    }
  }
}

# We add the secret value to the secret
resource "aws_secretsmanager_secret_version" "spoke_vpc_information" {
  secret_id     = data.aws_secretsmanager_secret.spoke_vpc_information.id
  secret_string = jsonencode(local.vpc_information)
}

# ---------- COMPUTE (NLB + EC2 INSTANCES) ----------
# Data resource to determine the latest Amazon Linux Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2*x86_64"]
  }
}

# NLB and EC2 instances
module "compute" {
  source   = "./modules/compute"
  for_each = module.ingress_vpcs

  vpc_name         = each.key
  vpc              = each.value
  vpc_cidr         = var.ingress_vpcs[each.key].cidr_block
  ami_id           = data.aws_ami.amazon_linux.id
  instance_type    = var.ingress_vpcs[each.key].instance_type
}

# ---------- ROUTING TO NETWORK FIREWALL RESOURCES (CREATED BY FIREWALL MANAGER) ----------
module "vpc_resources" {
  for_each = module.ingress_vpcs
  source   = "./modules/vpc-resources"

  vpc_id     = each.value.vpc_attributes.id
  vpc_name   = each.key
  igw_id     = each.value.internet_gateway[0].id
  aws_region = var.aws_region
  azs        = each.value.azs
  firewall_manager_information = {
    name = "ingress-fms-policy"
    id   = data.aws_secretsmanager_secret_version.firewall_manager.secret_string
  }
}

module "vpc_routes" {
  for_each = module.ingress_vpcs
  source   = "./modules/vpc-routes"

  public_subnet_route_tables   = { for k, v in each.value.rt_attributes_by_type_by_az.public : k => v.id }
  firewall_subnet_route_tables = module.vpc_resources[each.key].firewall_route_tables
  igw_route_table              = module.vpc_resources[each.key].igw_route_table
  internet_gateway             = each.value.internet_gateway[0].id
  firewall_endpoints           = module.vpc_resources[each.key].firewall_endpoints
  public_subnet_cidrs          = var.ingress_vpcs[each.key].public_subnet_cidrs
  azs                          = each.value.azs
}