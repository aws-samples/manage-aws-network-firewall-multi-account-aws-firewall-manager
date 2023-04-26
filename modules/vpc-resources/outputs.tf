/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/vpc-resources/outputs.tf ---

output "firewall_endpoints" {
  description = "AWS Network Firewall endpoints."
  value       = { for i in data.aws_networkfirewall_firewall.anfw.firewall_status[0].sync_states : i.availability_zone => i.attachment[0].endpoint_id }
}

output "firewall_route_tables" {
  description = "Firewall route table IDs."
  value       = { for i, az in var.azs : az => data.aws_route_table.firewall_route_tables[i].id }
}

output "internet_gateway" {
  description = "Internet gateway ID."
  value       = data.aws_internet_gateway.igw.id
}

output "igw_route_table" {
  description = "Internet gateway route table ID."
  value       = aws_route_table.igw_route_table.id
}