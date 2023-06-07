<!-- BEGIN_TF_DOCS -->
# Central AWS Account

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | = 4.67.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | = 4.67.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_hubspoke"></a> [hubspoke](#module\_hubspoke) | aws-ia/network-hubandspoke/aws | 3.0.0 |

## Resources

| Name | Type |
|------|------|
| [aws_ec2_transit_gateway.transit_gateway](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/ec2_transit_gateway) | resource |
| [aws_fms_policy.ingress_policy](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/fms_policy) | resource |
| [aws_kms_key.secrets_key](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/kms_key) | resource |
| [aws_networkfirewall_firewall_policy.central_inspection_policy](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/networkfirewall_firewall_policy) | resource |
| [aws_networkfirewall_rule_group.allow_ingress](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/networkfirewall_rule_group) | resource |
| [aws_networkfirewall_rule_group.drop_east_west](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/networkfirewall_rule_group) | resource |
| [aws_networkfirewall_rule_group.drop_remote](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/networkfirewall_rule_group) | resource |
| [aws_ram_principal_association.principal_association](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/ram_principal_association) | resource |
| [aws_ram_resource_association.tgw_share](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/ram_resource_association) | resource |
| [aws_ram_resource_share.resource_share](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/ram_resource_share) | resource |
| [aws_secretsmanager_secret.firewall_manager](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret.spoke_vpc_information](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret.transit_gateway](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret_version.firewall_manager](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/secretsmanager_secret_version) | resource |
| [aws_secretsmanager_secret_version.transit_gateway](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/secretsmanager_secret_version) | resource |
| [aws_caller_identity.aws_central_account](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.policy_kms_document](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.secrets_resource_policy_reading](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.secrets_resource_policy_writing](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/iam_policy_document) | data source |
| [aws_organizations_organization.org](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/organizations_organization) | data source |
| [aws_secretsmanager_secret_version.spoke_vpc_information](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/secretsmanager_secret_version) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS Region to use. | `string` | `"us-east-1"` | no |
| <a name="input_identifier"></a> [identifier](#input\_identifier) | Project identifier. | `string` | `"nis341-central"` | no |
| <a name="input_inspection_vpc"></a> [inspection\_vpc](#input\_inspection\_vpc) | Definition of Central VPCs - Inspection and Shared Services. | `any` | <pre>{<br>  "cidr_block": "10.100.0.0/24",<br>  "endpoints_subnet_cidrs": [<br>    "10.100.0.48/28",<br>    "10.100.0.64/28",<br>    "10.100.0.80/28"<br>  ],<br>  "name": "inspection-vpc",<br>  "number_azs": 2,<br>  "public_subnet_cidrs": [<br>    "10.100.0.0/28",<br>    "10.100.0.16/28",<br>    "10.100.0.32/28"<br>  ],<br>  "tgw_subnet_cidrs": [<br>    "10.100.0.96/28",<br>    "10.100.0.112/28",<br>    "10.100.0.128/28"<br>  ]<br>}</pre> | no |
| <a name="input_network_supernet"></a> [network\_supernet](#input\_network\_supernet) | Supernet CIDR to identify all the VPCs in the network. | `string` | `"10.0.0.0/8"` | no |
| <a name="input_secrets_names"></a> [secrets\_names](#input\_secrets\_names) | Secrets names - shared variable between AWS Accounts. | `map(string)` | <pre>{<br>  "firewall_manager": "firewall_manager_identifier",<br>  "spoke_vpc_information": "spoke_vpc_information",<br>  "transit_gateway": "transit_gateway_identifier"<br>}</pre> | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->