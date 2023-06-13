/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- spoke_account/variables.tf ---

variable "identifier" {
  type        = string
  description = "Project identifier."
  default     = "nis341-spoke"
}

variable "aws_region" {
  type        = string
  description = "AWS Region to use."
  default     = "eu-north-1"
}

variable "ingress_vpcs" {
  type        = any
  description = "Ingress VPCs to create in both AWS Regions."
  default = {
    ingress1 = {
      name                  = "ingress1"
      number_azs            = 2
      cidr_block            = "10.0.0.0/16"
      firewall_subnet_cidrs = ["10.0.0.0/28", "10.0.0.16/28", "10.0.0.32/28"]
      public_subnet_cidrs   = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
      workload_subnet_cidrs = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
      tgw_subnet_cidrs      = ["10.0.7.0/28", "10.0.7.16/28", "10.0.7.32/28"]
      instance_type         = "t3.micro"
    }
    ingress2 = {
      name                  = "ingress2"
      number_azs            = 2
      cidr_block            = "10.1.0.0/16"
      firewall_subnet_cidrs = ["10.1.0.0/28", "10.1.0.16/28", "10.1.0.32/28"]
      public_subnet_cidrs   = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
      workload_subnet_cidrs = ["10.1.4.0/24", "10.1.5.0/24", "10.1.6.0/24"]
      tgw_subnet_cidrs      = ["10.1.7.0/28", "10.1.7.16/28", "10.1.7.32/28"]
      instance_type         = "t3.micro"
    }
  }
}

variable "secrets_names" {
  type        = map(string)
  description = "Secrets names - shared variable between AWS Accounts."

  default = {
    transit_gateway       = "transit_gateway_identifier"
    firewall_manager      = "firewall_manager_identifier"
    spoke_vpc_information = "spoke_vpc_information"
  }
}

variable "central_account_id" {
  type        = string
  description = "AWS Central Account ID."
}