/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/vpc-routes/variables.tf ---

variable "public_subnet_route_tables" {
  type        = map(string)
  description = "Public subnet route table IDs."
}

variable "firewall_subnet_route_tables" {
  type        = map(string)
  description = "Firewall subnet route table IDs."
}

variable "igw_route_table" {
  type        = string
  description = "Firewall subnet route table IDs."
}

variable "internet_gateway" {
  type        = string
  description = "Internet gateway ID."
}

variable "firewall_endpoints" {
  type        = map(string)
  description = "AWS Network Firewall endpoints."
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "Public subnets CIDR blocks."
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones used in the VPC."
}