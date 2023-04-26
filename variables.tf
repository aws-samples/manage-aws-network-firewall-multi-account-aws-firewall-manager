/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- root/variables.tf ---

variable "identifier" {
  type        = string
  description = "Project identifier."
  default     = "nis341"
}

variable "aws_region" {
  type        = string
  description = "AWS Region to use."
  default     = "us-east-1"
}

variable "network_supernet" {
  type        = string
  description = "Supernet CIDR to identify all the VPCs in the network."
  default     = "10.0.0.0/8"
}

variable "ingress_vpcs" {
  type        = any
  description = "Ingress VPCs to create in both AWS Regions."
  default = {
    ingress1 = {
      name                  = "ingress1-us-east-1"
      number_azs            = 2
      cidr_block            = "10.0.0.0/16"
      firewall_subnet_cidrs = ["10.0.0.0/28", "10.0.0.16/28", "10.0.0.32/28"]
      public_subnet_cidrs   = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
      workload_subnet_cidrs = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
      tgw_subnet_cidrs      = ["10.0.7.0/28", "10.0.7.16/28", "10.0.7.32/28"]
      instance_type         = "t2.micro"
    }
    ingress2 = {
      name                  = "ingress2-us-east-1"
      number_azs            = 2
      cidr_block            = "10.1.0.0/16"
      firewall_subnet_cidrs = ["10.1.0.0/28", "10.1.0.16/28", "10.1.0.32/28"]
      public_subnet_cidrs   = ["10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"]
      workload_subnet_cidrs = ["10.1.4.0/24", "10.1.5.0/24", "10.1.6.0/24"]
      tgw_subnet_cidrs      = ["10.1.7.0/28", "10.1.7.16/28", "10.1.7.32/28"]
      instance_type         = "t2.micro"
    }
  }
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

# AWS Accounts Access Key and Secret Access Key (from .tfvars file)
variable "central_account_accesskey" {
  type        = string
  description = "Central AWS Account - Access Key."
}

variable "central_account_secretaccesskey" {
  type        = string
  description = "Central AWS Account - Secret Access Key."
}

variable "central_account_sessiontoken" {
  type        = string
  description = "Central AWS Account - Session Token."
}

variable "spoke_account_accesskey" {
  type        = string
  description = "Spoke AWS Account - Access Key."
}

variable "spoke_account_secretaccesskey" {
  type        = string
  description = "Spoke AWS Account - Secret Access Key."
}

variable "spoke_account_sessiontoken" {
  type        = string
  description = "Spoke AWS Account - Session Token."
}