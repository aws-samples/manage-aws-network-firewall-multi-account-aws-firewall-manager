/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: MIT-0 */

# --- root/firewall_policy.tf ---

# ---------- NETWORK FIREWALL POLICY (CENTRAL INSPECTION) ----------
resource "aws_networkfirewall_firewall_policy" "central_inspection_policy" {
  name = "central-firewall-policy-${var.identifier}"

  firewall_policy {
    # Stateless configuration
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateless_rule_group_reference {
      priority     = 10
      resource_arn = aws_networkfirewall_rule_group.drop_remote.arn
    }

    # Stateful configuration
    stateful_engine_options {
      rule_order = "DEFAULT_ACTION_ORDER"
    }
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.drop_east_west.arn
    }
  }
}

# ---------- STATELESS RULE GROUP - DROPPING SSH OR RDP ----------
resource "aws_networkfirewall_rule_group" "drop_remote" {
  capacity = 2
  name     = "drop-remote-${var.identifier}"
  type     = "STATELESS"
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {

        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              protocols = [6]
              source {
                address_definition = "0.0.0.0/0"
              }
              source_port {
                from_port = 0
                to_port   = 65535
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
              destination_port {
                from_port = 22
                to_port   = 22
              }
            }
          }
        }
      }
    }
  }
}

# ---------- STATEFUL RULE GROUP - ALLOWING INGRESS HTTP ACCESS (STRICT) ----------
resource "aws_networkfirewall_rule_group" "allow_ingress" {
  capacity = 50
  name     = "allow-ingress-${var.identifier}"
  type     = "STATEFUL"
  rule_group {
    rules_source {
      rules_string = <<EOF
      pass tcp $EXTERNAL_NET any -> $HOME_NET any (msg: "Allowing HTTP ingress access"; sid:2; rev:1;)
      EOF
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}

# ---------- STATEFUL RULE GROUP - BLOCKING TRAFFIC BETWEEN SPOKE VPCS (DEFAULT) ----------
resource "aws_networkfirewall_rule_group" "drop_east_west" {
  capacity = 50
  name     = "allow-egress-${var.identifier}"
  type     = "STATEFUL"
  rule_group {
    rule_variables {
      ip_sets {
        key = "NETWORK"
        ip_set {
          definition = [var.network_supernet]
        }
      }
    }
    rules_source {
      rules_string = <<EOF
      drop icmp $NETWORK any -> $NETWORK any (msg: "Blocking East-West traffic"; sid:1; rev:1;)
      drop tcp $NETWORK any -> $NETWORK any (msg: "Blocking East-West traffic"; sid:2; rev:1;)
      EOF
    }
    stateful_rule_options {
      rule_order = "DEFAULT_ACTION_ORDER"
    }
  }
}