/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- modules/compute/locals.tf ---

locals {
  instance_sg = {
    name        = "${var.vpc_name}-instance_sg"
    description = "Security Group for EC2 instances."
    ingress = {
      https = {
        description = "Allowing HTTP"
        from        = 80
        to          = 80
        protocol    = "tcp"
        cidr_blocks = [var.vpc_cidr]
      }
    }
    egress = {
      any = {
        description = "Any traffic"
        from        = 0
        to          = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
  }
}