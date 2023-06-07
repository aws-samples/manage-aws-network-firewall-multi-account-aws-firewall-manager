/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/compute/variables.tf ---

variable "vpc_name" {
  type        = string
  description = "VPC name."
}

variable "vpc" {
  type        = any
  description = "VPC Information."
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block."
}

variable "ami_id" {
  type        = string
  description = "AMI ID."
}

variable "instance_type" {
  type        = string
  description = "Instance type."
}



