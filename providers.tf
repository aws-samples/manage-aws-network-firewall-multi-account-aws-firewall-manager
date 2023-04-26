/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- root/providers.tf ---

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.57.0"
    }
  }
}

# Provider definition for central Networking/Security AWS Account
provider "aws" {
  alias = "awscentral"

  region     = var.aws_region
  access_key = var.central_account_accesskey
  secret_key = var.central_account_secretaccesskey
  token      = var.central_account_sessiontoken
}

# Provider definition for spoke AWS Account
provider "aws" {
  alias = "awsspoke"

  region     = var.aws_region
  access_key = var.spoke_account_accesskey
  secret_key = var.spoke_account_secretaccesskey
  token      = var.spoke_account_sessiontoken
}