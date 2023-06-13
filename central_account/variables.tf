/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- central_account/variables.tf ---

variable "identifier" {
  type        = string
  description = "Project identifier."
  default     = "nis341-central"
}

variable "aws_region" {
  type        = string
  description = "AWS Region to use."
  default     = "eu-north-1"
}

variable "network_supernet" {
  type        = string
  description = "Supernet CIDR to identify all the VPCs in the network."
  default     = "10.0.0.0/8"
}

variable "inspection_vpc" {
  type        = any
  description = "Definition of Central VPCs - Inspection and Shared Services."
  default = {
    name                   = "inspection-vpc"
    cidr_block             = "10.100.0.0/24"
    number_azs             = 2
    public_subnet_cidrs    = ["10.100.0.0/28", "10.100.0.16/28", "10.100.0.32/28"]
    endpoints_subnet_cidrs = ["10.100.0.48/28", "10.100.0.64/28", "10.100.0.80/28"]
    tgw_subnet_cidrs       = ["10.100.0.96/28", "10.100.0.112/28", "10.100.0.128/28"]
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