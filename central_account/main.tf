/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- root/main_central_account.tf ---

# ---------- AWS ORGANIZATIONS AND ACCOUNT INFORMATION ----------
data "aws_caller_identity" "aws_central_account" {}
data "aws_organizations_organization" "org" {}

# ---------- AWS FIREWALL MANAGER - INGRESS POLICY ----------
resource "aws_fms_policy" "ingress_policy" {
  name          = "ingress-fms-policy"
  description   = "FMS Policy - Ingress VPCs."
  resource_type = "AWS::EC2::VPC"

  remediation_enabled                = true
  delete_all_policy_resources        = true
  delete_unused_fm_managed_resources = true

  exclude_resource_tags = false
  resource_tags = {
    fms_ingress = true
  }

  security_service_policy_data {
    type = "NETWORK_FIREWALL"

    managed_service_data = jsonencode({
      type = "NETWORK_FIREWALL"
      networkFirewallStatelessRuleGroupReferences = [{
        resourceARN = aws_networkfirewall_rule_group.drop_remote.arn
        priority    = 1
      }]
      networkFirewallStatelessDefaultActions         = ["aws:forward_to_sfe"]
      networkFirewallStatelessFragmentDefaultActions = ["aws:forward_to_sfe"]
      networkFirewallStatelessCustomActions          = []
      networkFirewallStatefulEngineOptions           = { ruleOrder = "STRICT_ORDER" }
      networkFirewallStatefulRuleGroupReferences = [{
        resourceARN = aws_networkfirewall_rule_group.allow_ingress.arn
        priority    = 1
      }]
      networkFirewallStatefulDefaultActions = ["aws:drop_strict", "aws:alert_strict"]
      networkFirewallOrchestrationConfig = {
        singleFirewallEndpointPerVPC = false
        allowedIPV4CidrList          = local.spoke_vpc_information.firewall_subnet_ids
        routeManagementAction        = "MONITOR"
        routeManagementTargetTypes   = ["InternetGateway"]
      }
      networkFirewallLoggingConfiguration = {
        logDestinationConfigs = [
          {
            logDestinationType = "S3",
            logType            = "FLOW",
            logDestination = {
              bucketName = "${var.log_destination_s3_arn}"
            }
          },
          {
            logDestinationType = "S3",
            logType            = "ALERT",
            logDestination = {
              bucketName = "${var.log_destination_s3_arn}"
            }
          }
        ]
        overrideExistingConfig = false
      }
    })
  }
}

resource "aws_secretsmanager_secret" "firewall_manager" {
  name = var.secrets_names.firewall_manager
  description = "AWS Firewall Manager policy ID - Central Account"
  kms_key_id = aws_kms_key.secrets_key.arn
  policy = data.aws_iam_policy_document.secrets_resource_policy_reading.json
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "firewall_manager" {
  secret_id = aws_secretsmanager_secret.firewall_manager.id
  secret_string = aws_fms_policy.ingress_policy.id
}


# ---------- AWS SECRETS MANAGER SECRET (SPOKE VPCs INFORMATION) ----------
resource "aws_secretsmanager_secret" "spoke_vpc_information" {
  name                    = var.secrets_names.spoke_vpc_information
  description             = "Spoke VPCs Information."
  kms_key_id              = aws_kms_key.secrets_key.arn
  policy                  = data.aws_iam_policy_document.secrets_resource_policy_writing.json
  recovery_window_in_days = 0
}

# ---------- HUB AND SPOKE ARCHITECTURE (CENTRAL INSPECTION & EGRESS, AND SHARED SERVICES) ----------
# AWS Transit Gateway
resource "aws_ec2_transit_gateway" "transit_gateway" {
  description                     = "Transit Gateway - ${var.identifier}"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  auto_accept_shared_attachments  = "enable"

  tags = {
    Name = "tgw-${var.identifier}"
  }
}

# We get the Spoke VPC Information from the Spoke Account (Secrets Manager)
data "aws_secretsmanager_secret_version" "spoke_vpc_information" {
  secret_id = aws_secretsmanager_secret.spoke_vpc_information.id
}

locals {
  spoke_vpc_information = jsondecode(data.aws_secretsmanager_secret_version.spoke_vpc_information.secret_string)["spoke_account"]
}

# We share the Transit Gateway ID with the AWS Organization (AWS Secrets Manager)
resource "aws_secretsmanager_secret" "transit_gateway" {
  name                    = var.secrets_names.transit_gateway
  description             = "AWS Transit Gateway ID - Central Account"
  kms_key_id              = aws_kms_key.secrets_key.arn
  policy                  = data.aws_iam_policy_document.secrets_resource_policy_reading.json
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "transit_gateway" {
  secret_id     = aws_secretsmanager_secret.transit_gateway.id
  secret_string = aws_ec2_transit_gateway.transit_gateway.id
}

# Hub and Spoke with Inspection & Egress VPC (with AWS Network Firewall) and Shared Services VPC
module "hubspoke" {
  source  = "aws-ia/network-hubandspoke/aws"
  version = "3.0.0"

  identifier         = var.identifier
  transit_gateway_id = aws_ec2_transit_gateway.transit_gateway.id
  network_definition = {
    type  = "CIDR"
    value = var.network_supernet
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
    number_vpcs     = try(local.spoke_vpc_information.number_spoke_vpcs, 0)
    vpc_information = try(local.spoke_vpc_information.vpc_information, {})
  }
}

# ---------- AWS RESOURCE ACCESS MANAGER ----------
# Resource Share
resource "aws_ram_resource_share" "resource_share" {
  name                      = "Networking Account Resource Share"
  allow_external_principals = false
}

# Principal Association
resource "aws_ram_principal_association" "principal_association" {
  principal          = data.aws_organizations_organization.org.arn
  resource_share_arn = aws_ram_resource_share.resource_share.arn
}

# Resource Association - AWS Transit Gateway
resource "aws_ram_resource_association" "tgw_share" {
  resource_arn       = aws_ec2_transit_gateway.transit_gateway.arn
  resource_share_arn = aws_ram_resource_share.resource_share.arn
}

# ---------- AWS SECRETS MANAGER RESOURCES ----------
# Secrets resource policy - reading secret values
data "aws_iam_policy_document" "secrets_resource_policy_reading" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"

      values = ["${data.aws_organizations_organization.org.id}"]
    }
  }
}

# Secrets resource policy - writing secret values
data "aws_iam_policy_document" "secrets_resource_policy_writing" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"

      values = ["${data.aws_organizations_organization.org.id}"]
    }
  }
}

# KMS Key to encrypt the secrets
resource "aws_kms_key" "secrets_key" {
  description             = "KMS Secrets Key - Central Account."
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.policy_kms_document.json

  tags = {
    Name = "kms-key-${var.identifier}"
  }
}

# KMS Policy
data "aws_iam_policy_document" "policy_kms_document" {
  statement {
    sid       = "Enable AWS Secrets Manager secrets decryption."
    effect    = "Allow"
    actions   = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"

      values = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:SecretARN"

      values = ["arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.aws_central_account.id}:secret:*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"

      values = ["${data.aws_organizations_organization.org.id}"]
    }
  }

  statement {
    sid       = "Enable IAM User Permissions"
    actions   = ["kms:*"]
    resources = ["arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.aws_central_account.id}:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.aws_central_account.id}:root"]
    }
  }
}