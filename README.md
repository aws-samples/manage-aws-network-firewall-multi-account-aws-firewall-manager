<!-- BEGIN_TF_DOCS -->
# Manage your AWS Network Firewall resources in multi-Account environments using AWS Firewall Manager - Terraform sample

In this repository, you will use [AWS Firewall Manager](https://aws.amazon.com/firewall-manager/) to deploy decentralized [AWS Network Firewall](https://aws.amazon.com/network-firewall/) resources between AWS Accounts. The purpose of the repository is to show how to create Firewall Manager rules using IaC (Terraform as an example) in a central Networking/Security AWS Account, while all the extra routing configuration needed in the Spoke AWS Accounts (to point the traffic to/from the Internet gateway via the firewall endpoints).

Aside the multi-Account Firewall Manager implementation, the repository also creates the following resources:

* Hub and Spoke architecture (with [AWS Transit Gateway](https://aws.amazon.com/transit-gateway/)) with centralized inspection in the central Networking/Security AWS Account - this Network Firewall resource is not managed by Firewall Manager.
* Two Spoke VPCs in the spoke AWS Account, both of them attached to the Transit Gateway. Each VPC also has a Network Load Balancer pointing to a target group of several EC2 instances (one created in each Availability Zone where you created resources).
* The Transit Gateway created in the central AWS Account is shared with the AWS Organization using [AWS Resource Access Manager](https://aws.amazon.com/ram/).

[ADD IMAGE HERE]

## Prerequities

* The repository uses two providers - as it expects two AWS Accounts. You can use a *terraform.tfvars* file (or environment variables) to pass the AWS Account information. Both AWS Accounts should have IAM user with appropriate permissions.
* If using two AWS Accounts, they should be in the same AWS Organizations to use AWS Firewall Manager. Check the [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/fms-prereq.html) to understand the prerequisites needed to enable Firewall Manager.
* Terraform installed.

## Code Principles

* Writing DRY (Do No Repeat Yourself) code using a modular design pattern.

## Usage

* Clone the repository.
* Edit the *variables.tf* to change the identifier (used to name some resources), the Ingress VPCs to create, the information about the Inspection VPC, or the network supernet to use.

## Deployment

* Use `terraform apply` to deploy the Hub and Spoke architecture in the central Account, and the spoke VPCs (with the NLB and EC2 instances) in the spoke Account.
* Uncomment lines 18 - 58 in *main\_central\_account.tf* and use `terraform apply` to create the Firewall Manager resource. Check in the spoke AWS Account that a Network Firewall resource is created in each spoke VPC you have created. Wait for the firewalls to be ready.
* Uncomment lines 31, and 80 - 107 in *main\_spoke\_account.tf* and use `terraform apply` to create the VPC routes via the firewall endpoints in the spoke VPCs.
  * Line 31 removes the default route (0.0.0.0/0) from the spoke VPCs to the Internet gateway.
  * Check the modules used in lines 80 - 107 (vpc-resources and vpc-routes) in the *modules* folder to understand how to get the resources created by Firewall Manager to create the VPC routes.

## Firewall policies

### AWS Firewall Manager - Decentralized ingress policy

You can find the Firewall Manager policy definition in the *main\_central\_account.tf* file:

```hcl
resource "aws_fms_policy" "ingress_policy" {
  name          = "ingress-fms-policy"
  description   = "FMS Policy - Ingress VPCs."
  resource_type = "AWS::EC2::VPC"

  remediation_enabled                = true
  delete_all_policy_resources        = true
  delete_unused_fm_managed_resources = true

  exclude_resource_tags = false
  resource_tags = {
    fms_ingress = true
  }

  security_service_policy_data {
    type = "NETWORK_FIREWALL"

    managed_service_data = jsonencode({
      type = "NETWORK_FIREWALL"
      networkFirewallStatelessRuleGroupReferences = [{
        resourceARN = aws_networkfirewall_rule_group.drop_remote.arn
        priority    = 1
      }]
      networkFirewallStatelessDefaultActions         = ["aws:forward_to_sfe"]
      networkFirewallStatelessFragmentDefaultActions = ["aws:forward_to_sfe"]
      networkFirewallStatelessCustomActions          = []
      networkFirewallStatefulEngineOptions           = { ruleOrder = "STRICT_ORDER" }
      networkFirewallStatefulRuleGroupReferences = [{
        resourceARN = aws_networkfirewall_rule_group.allow_ingress.arn
        priority    = 1
      }]
      networkFirewallStatefulDefaultActions = ["aws:drop_strict", "aws:alert_strict"]
      networkFirewallOrchestrationConfig = {
        singleFirewallEndpointPerVPC = false
        allowedIPV4CidrList          = local.fms_ingress_allowedIPV4CidrList
        routeManagementAction        = "MONITOR"
        routeManagementTargetTypes   = ["InternetGateway"]
      }
    })
  }
}
```

You can check the [AWS documentation](https://docs.aws.amazon.com/waf/latest/developerguide/network-firewall-policies.html) and [Terraform Registry resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/fms_policy) to get more information about the format and content of this resource. Regarding the firewall policy itself:

* The stateless rule group blocks any SSH or RDP traffic. You can see this rule group defined in the *firewall\_policy.tf* file. Traffic not blocked will be sent to
* The stateful rule group (STRICT) blocks any traffic by default, and it only has one pass rule allowing traffic from the Internet to any resource inside the VPC.

```
pass tcp $EXTERNAL_NET any -> $HOME_NET any (msg: "Allowing HTTP ingress access"; sid:2; rev:1;)
```

### AWS Network Firewall - Centralized policy

You can find the Firewall Manager policy definition in the *firewall\_policy.tf* file:

```hcl
resource "aws_networkfirewall_firewall_policy" "central_inspection_policy" {
  provider = aws.awscentral

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
```

You can check the [AWS documentation](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html) and [Terraform Registry resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_firewall_policy) to get more information about the format and content of this resource. Regarding the firewall policy itself:

* The stateless rule group blocks any SSH or RDP traffic. You can see this rule group defined in the *firewall\_policy.tf* file. Traffic not blocked will be sent to
* The stateful rule group (DEFAULT) blocks any ICMP or TCP traffic from VPCs in the network (supernet defined in the $NETWORK variable).

```
drop icmp $NETWORK any -> $NETWORK any (msg: "Blocking East-West traffic"; sid:1; rev:1;)
drop tcp $NETWORK any -> $NETWORK any (msg: "Blocking East-West traffic"; sid:2; rev:1;)
```

## Cleanup

* Remove the VPC routing created via the firewall endpoints using `terraform destroy -target="module.vpc_routes"`.
* You can now remove the AWS Firewall Manager policy, which will automatically remove the Network Firewall resources, subnets and route tables created by the service - `terraform destroy -target="aws_fms_policy.ingress_policy". Wait for these resources to be completely removed before continuing with the cleanup.
* Now you can remove the rest of the environment by using `terraform destroy`. You will need to comment the definition of the *vpc_resources* and *vpc_routes* modules to avoid errors during the planning phase.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.`

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 4.57.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 4.64.0 |
| <a name="provider_aws.awscentral"></a> [aws.awscentral](#provider\_aws.awscentral) | 4.64.0 |
| <a name="provider_aws.awsspoke"></a> [aws.awsspoke](#provider\_aws.awsspoke) | 4.64.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_compute"></a> [compute](#module\_compute) | ./modules/compute | n/a |
| <a name="module_hubspoke"></a> [hubspoke](#module\_hubspoke) | aws-ia/network-hubandspoke/aws | 3.0.0 |
| <a name="module_ingress_vpcs"></a> [ingress\_vpcs](#module\_ingress\_vpcs) | git::https://github.com/pablo19sc/terraform-aws-vpc | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_ec2_transit_gateway.transit_gateway](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_transit_gateway) | resource |
| [aws_iam_instance_profile.ec2_instance_profile](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_policy_attachment.ssm_iam_role_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy_attachment) | resource |
| [aws_iam_role.role_ec2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_networkfirewall_firewall_policy.central_inspection_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_firewall_policy) | resource |
| [aws_networkfirewall_rule_group.allow_ingress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_rule_group) | resource |
| [aws_networkfirewall_rule_group.drop_east_west](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_rule_group) | resource |
| [aws_networkfirewall_rule_group.drop_remote](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_rule_group) | resource |
| [aws_ram_principal_association.principal_association](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ram_principal_association) | resource |
| [aws_ram_resource_association.tgw_share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ram_resource_association) | resource |
| [aws_ram_resource_share.resource_share](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ram_resource_share) | resource |
| [aws_ami.amazon_linux](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_caller_identity.aws_central_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_caller_identity.aws_spoke_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_organizations_organization.org](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/organizations_organization) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_central_account_accesskey"></a> [central\_account\_accesskey](#input\_central\_account\_accesskey) | Central AWS Account - Access Key. | `string` | n/a | yes |
| <a name="input_central_account_secretaccesskey"></a> [central\_account\_secretaccesskey](#input\_central\_account\_secretaccesskey) | Central AWS Account - Secret Access Key. | `string` | n/a | yes |
| <a name="input_central_account_sessiontoken"></a> [central\_account\_sessiontoken](#input\_central\_account\_sessiontoken) | Central AWS Account - Session Token. | `string` | n/a | yes |
| <a name="input_spoke_account_accesskey"></a> [spoke\_account\_accesskey](#input\_spoke\_account\_accesskey) | Spoke AWS Account - Access Key. | `string` | n/a | yes |
| <a name="input_spoke_account_secretaccesskey"></a> [spoke\_account\_secretaccesskey](#input\_spoke\_account\_secretaccesskey) | Spoke AWS Account - Secret Access Key. | `string` | n/a | yes |
| <a name="input_spoke_account_sessiontoken"></a> [spoke\_account\_sessiontoken](#input\_spoke\_account\_sessiontoken) | Spoke AWS Account - Session Token. | `string` | n/a | yes |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS Region to use. | `string` | `"us-east-1"` | no |
| <a name="input_identifier"></a> [identifier](#input\_identifier) | Project identifier. | `string` | `"nis341"` | no |
| <a name="input_ingress_vpcs"></a> [ingress\_vpcs](#input\_ingress\_vpcs) | Ingress VPCs to create in both AWS Regions. | `any` | <pre>{<br>  "ingress1": {<br>    "cidr_block": "10.0.0.0/16",<br>    "firewall_subnet_cidrs": [<br>      "10.0.0.0/28",<br>      "10.0.0.16/28",<br>      "10.0.0.32/28"<br>    ],<br>    "instance_type": "t2.micro",<br>    "name": "ingress1-us-east-1",<br>    "number_azs": 2,<br>    "public_subnet_cidrs": [<br>      "10.0.1.0/24",<br>      "10.0.2.0/24",<br>      "10.0.3.0/24"<br>    ],<br>    "tgw_subnet_cidrs": [<br>      "10.0.7.0/28",<br>      "10.0.7.16/28",<br>      "10.0.7.32/28"<br>    ],<br>    "workload_subnet_cidrs": [<br>      "10.0.4.0/24",<br>      "10.0.5.0/24",<br>      "10.0.6.0/24"<br>    ]<br>  },<br>  "ingress2": {<br>    "cidr_block": "10.1.0.0/16",<br>    "firewall_subnet_cidrs": [<br>      "10.1.0.0/28",<br>      "10.1.0.16/28",<br>      "10.1.0.32/28"<br>    ],<br>    "instance_type": "t2.micro",<br>    "name": "ingress2-us-east-1",<br>    "number_azs": 2,<br>    "public_subnet_cidrs": [<br>      "10.1.1.0/24",<br>      "10.1.2.0/24",<br>      "10.1.3.0/24"<br>    ],<br>    "tgw_subnet_cidrs": [<br>      "10.1.7.0/28",<br>      "10.1.7.16/28",<br>      "10.1.7.32/28"<br>    ],<br>    "workload_subnet_cidrs": [<br>      "10.1.4.0/24",<br>      "10.1.5.0/24",<br>      "10.1.6.0/24"<br>    ]<br>  }<br>}</pre> | no |
| <a name="input_inspection_vpc"></a> [inspection\_vpc](#input\_inspection\_vpc) | Definition of Central VPCs - Inspection and Shared Services. | `any` | <pre>{<br>  "cidr_block": "10.100.0.0/24",<br>  "endpoints_subnet_cidrs": [<br>    "10.100.0.48/28",<br>    "10.100.0.64/28",<br>    "10.100.0.80/28"<br>  ],<br>  "name": "inspection-vpc",<br>  "number_azs": 2,<br>  "public_subnet_cidrs": [<br>    "10.100.0.0/28",<br>    "10.100.0.16/28",<br>    "10.100.0.32/28"<br>  ],<br>  "tgw_subnet_cidrs": [<br>    "10.100.0.96/28",<br>    "10.100.0.112/28",<br>    "10.100.0.128/28"<br>  ]<br>}</pre> | no |
| <a name="input_network_supernet"></a> [network\_supernet](#input\_network\_supernet) | Supernet CIDR to identify all the VPCs in the network. | `string` | `"10.0.0.0/8"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->