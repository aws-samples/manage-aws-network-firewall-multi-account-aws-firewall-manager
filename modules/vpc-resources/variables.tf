/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/vpc-resources/variables.tf ---

variable "vpc_id" {
  type        = string
  description = "Amazon VPC ID."
}

variable "vpc_name" {
  type        = string
  description = "VPC name."
}

variable "aws_region" {
  type        = string
  description = "AWS Region where the AWS Network Firewall resource has been created."
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones used in the VPC."
}

variable "firewall_manager_information" {
  type = object({
    name = string
    id   = string
  })
}