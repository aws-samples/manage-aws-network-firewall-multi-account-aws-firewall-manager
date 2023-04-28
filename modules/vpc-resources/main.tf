/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/vpc-resources/main.tf ---

# ---------- AWS ACCOUNT ----------
data "aws_caller_identity" "aws_account" {}

# ---------- DATA SOURCE: AWS Network Firewall ----------
data "aws_networkfirewall_firewall" "anfw" {
  arn = "arn:aws:network-firewall:${var.aws_region}:${data.aws_caller_identity.aws_account.account_id}:firewall/FMManagedNetworkFirewall${var.firewall_manager_information.name}${var.firewall_manager_information.id}${var.vpc_id}"
}

# ---------- DATA SOURCE: SUBNET AND ROUTE TABLE ----------
data "aws_subnet" "firewall_subnets" {
  count = length(var.azs)

  vpc_id            = var.vpc_id
  availability_zone = var.azs[count.index]

  filter {
    name   = "tag:Name"
    values = ["AWSFirewallManagerManagedResource"]
  }
}

data "aws_route_table" "firewall_route_tables" {
  count = length(var.azs)

  subnet_id = data.aws_subnet.firewall_subnets[count.index].id
}

# ---------- DATA SOURCE: Internet Gateway & RESOURCE: Internet gateway route table ----------

resource "aws_route_table" "igw_route_table" {
  vpc_id = var.vpc_id

  tags = {
    Name = "igw-route-table-${var.vpc_name}"
  }
}

resource "aws_route_table_association" "igw_route_table_assoc" {
  gateway_id     = var.igw_id
  route_table_id = aws_route_table.igw_route_table.id
}