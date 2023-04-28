/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- root/main_central_account.tf ---

# ---------- AWS ACCOUNT ID ----------
data "aws_caller_identity" "aws_central_account" {
  provider = aws.awscentral
}

# ---------- LOCAL VARIABLES ----------
# List of subnet CIDRs (firewall) for the endpoint creation in Firewall Manager
locals {
  fms_ingress_allowedIPV4CidrList = flatten(values({ for k, v in var.ingress_vpcs : k => slice(v.firewall_subnet_cidrs, 0, v.number_azs) }))
}

# ---------- AWS FIREWALL MANAGER - INGRESS POLICY ----------
# resource "aws_fms_policy" "ingress_policy" {
#   provider      = aws.awscentral
#   name          = "ingress-fms-policy"
#   description   = "FMS Policy - Ingress VPCs."
#   resource_type = "AWS::EC2::VPC"

#   remediation_enabled                = true
#   delete_all_policy_resources        = true
#   delete_unused_fm_managed_resources = true

#   exclude_resource_tags = false
#   resource_tags = {
#     fms_ingress = true
#   }

#   security_service_policy_data {
#     type = "NETWORK_FIREWALL"

#     managed_service_data = jsonencode({
#       type = "NETWORK_FIREWALL"
#       networkFirewallStatelessRuleGroupReferences = [{
#         resourceARN = aws_networkfirewall_rule_group.drop_remote.arn
#         priority    = 1
#       }]
#       networkFirewallStatelessDefaultActions         = ["aws:forward_to_sfe"]
#       networkFirewallStatelessFragmentDefaultActions = ["aws:forward_to_sfe"]
#       networkFirewallStatelessCustomActions          = []
#       networkFirewallStatefulEngineOptions           = { ruleOrder = "STRICT_ORDER" }
#       networkFirewallStatefulRuleGroupReferences = [{
#         resourceARN = aws_networkfirewall_rule_group.allow_ingress.arn
#         priority    = 1
#       }]
#       networkFirewallStatefulDefaultActions = ["aws:drop_strict", "aws:alert_strict"]
#       networkFirewallOrchestrationConfig = {
#         singleFirewallEndpointPerVPC = false
#         allowedIPV4CidrList          = local.fms_ingress_allowedIPV4CidrList
#         routeManagementAction        = "MONITOR"
#         routeManagementTargetTypes   = ["InternetGateway"]
#       }
#     })
#   }
# }

# ---------- HUB AND SPOKE ARCHITECTURE (CENTRAL INSPECTION & EGRESS, AND SHARED SERVICES) ----------
# AWS Transit Gateway
resource "aws_ec2_transit_gateway" "transit_gateway" {
  provider = aws.awscentral

  description                     = "Transit Gateway - ${var.identifier}"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  auto_accept_shared_attachments  = "enable"

  tags = {
    Name = "tgw-${var.identifier}"
  }
}

# Hub and Spoke with Inspection & Egress VPC (with AWS Network Firewall) and Shared Services VPC
module "hubspoke" {
  source    = "aws-ia/network-hubandspoke/aws"
  version   = "3.0.0"
  providers = { aws = aws.awscentral }

  identifier         = var.identifier
  transit_gateway_id = aws_ec2_transit_gateway.transit_gateway.id
  network_definition = {
    type  = "CIDR"
    value = "10.0.0.0/8"
  }

  central_vpcs = {
    inspection = {
      name       = var.inspection_vpc.name
      cidr_block = var.inspection_vpc.cidr_block
      az_count   = var.inspection_vpc.number_azs

      aws_network_firewall = {
        name       = "ANFW-${var.identifier}"
        policy_arn = aws_networkfirewall_firewall_policy.central_inspection_policy.arn
      }

      subnets = {
        public          = { cidrs = slice(var.inspection_vpc.public_subnet_cidrs, 0, var.inspection_vpc.number_azs) }
        endpoints       = { cidrs = slice(var.inspection_vpc.endpoints_subnet_cidrs, 0, var.inspection_vpc.number_azs) }
        transit_gateway = { cidrs = slice(var.inspection_vpc.tgw_subnet_cidrs, 0, var.inspection_vpc.number_azs) }
      }
    }
  }

  spoke_vpcs = {
    number_vpcs = length(var.ingress_vpcs)
    vpc_information = { for k, v in module.ingress_vpcs : k => {
      vpc_id                        = v.vpc_attributes.id
      transit_gateway_attachment_id = v.transit_gateway_attachment_id
    } }
  }
}

# ---------- AWS RESOURCE ACCESS MANAGER ----------
# Resource Share
resource "aws_ram_resource_share" "resource_share" {
  provider = aws.awscentral

  name                      = "Networking Account Resource Share"
  allow_external_principals = false
}

# We get the AWS Organizations ARN to use in the RAM principal assocation
data "aws_organizations_organization" "org" {}

# Principal Association
resource "aws_ram_principal_association" "principal_association" {
  provider = aws.awscentral

  principal          = data.aws_organizations_organization.org.arn
  resource_share_arn = aws_ram_resource_share.resource_share.arn
}

# Resource Association - AWS Transit Gateway
resource "aws_ram_resource_association" "tgw_share" {
  provider           = aws.awscentral
  resource_arn       = aws_ec2_transit_gateway.transit_gateway.arn
  resource_share_arn = aws_ram_resource_share.resource_share.arn
}