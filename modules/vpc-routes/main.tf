/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/vpc-routes/main.tf ---

# VPC ROUTE: Internet gateway to public subnets 
resource "aws_route" "igw_to_public_via_firewall" {
  count = length(var.azs)

  route_table_id         = var.igw_route_table
  destination_cidr_block = var.public_subnet_cidrs[count.index]
  vpc_endpoint_id        = var.firewall_endpoints[var.azs[count.index]]
}

# VPC ROUTE: Public subnets to Internet (0.0.0.0/0)
resource "aws_route" "public_to_internet_via_firewall" {
  for_each = var.public_subnet_route_tables

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = var.firewall_endpoints[each.key]
}

# VPC ROUTE: Firewall subnets to Internet (0.0.0.0/0)
resource "aws_route" "firewall_to_internet" {
  for_each = var.firewall_subnet_route_tables

  route_table_id         = each.value
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = var.internet_gateway
}