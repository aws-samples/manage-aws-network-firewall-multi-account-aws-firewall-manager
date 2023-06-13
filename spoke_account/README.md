<!-- BEGIN_TF_DOCS -->
# Spoke AWS Account

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
| <a name="module_compute"></a> [compute](#module\_compute) | ./modules/compute | n/a |
| <a name="module_ingress_vpcs"></a> [ingress\_vpcs](#module\_ingress\_vpcs) | aws-ia/vpc/aws | = 4.2.1 |
| <a name="module_vpc_resources"></a> [vpc\_resources](#module\_vpc\_resources) | ./modules/vpc-resources | n/a |
| <a name="module_vpc_routes"></a> [vpc\_routes](#module\_vpc\_routes) | ./modules/vpc-routes | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_secretsmanager_secret_version.spoke_vpc_information](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/resources/secretsmanager_secret_version) | resource |
| [aws_ami.amazon_linux](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/ami) | data source |
| [aws_caller_identity.aws_spoke_account](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/caller_identity) | data source |
| [aws_secretsmanager_secret.firewall_manager](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/secretsmanager_secret) | data source |
| [aws_secretsmanager_secret.spoke_vpc_information](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/secretsmanager_secret) | data source |
| [aws_secretsmanager_secret.transit_gateway](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/secretsmanager_secret) | data source |
| [aws_secretsmanager_secret_version.firewall_manager](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/secretsmanager_secret_version) | data source |
| [aws_secretsmanager_secret_version.transit_gateway](https://registry.terraform.io/providers/hashicorp/aws/4.67.0/docs/data-sources/secretsmanager_secret_version) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_central_account_id"></a> [central\_account\_id](#input\_central\_account\_id) | AWS Central Account ID. | `string` | n/a | yes |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS Region to use. | `string` | `"eu-north-1"` | no |
| <a name="input_identifier"></a> [identifier](#input\_identifier) | Project identifier. | `string` | `"nis341-spoke"` | no |
| <a name="input_ingress_vpcs"></a> [ingress\_vpcs](#input\_ingress\_vpcs) | Ingress VPCs to create in both AWS Regions. | `any` | <pre>{<br>  "ingress1": {<br>    "cidr_block": "10.0.0.0/16",<br>    "firewall_subnet_cidrs": [<br>      "10.0.0.0/28",<br>      "10.0.0.16/28",<br>      "10.0.0.32/28"<br>    ],<br>    "instance_type": "t3.micro",<br>    "name": "ingress1",<br>    "number_azs": 2,<br>    "public_subnet_cidrs": [<br>      "10.0.1.0/24",<br>      "10.0.2.0/24",<br>      "10.0.3.0/24"<br>    ],<br>    "tgw_subnet_cidrs": [<br>      "10.0.7.0/28",<br>      "10.0.7.16/28",<br>      "10.0.7.32/28"<br>    ],<br>    "workload_subnet_cidrs": [<br>      "10.0.4.0/24",<br>      "10.0.5.0/24",<br>      "10.0.6.0/24"<br>    ]<br>  },<br>  "ingress2": {<br>    "cidr_block": "10.1.0.0/16",<br>    "firewall_subnet_cidrs": [<br>      "10.1.0.0/28",<br>      "10.1.0.16/28",<br>      "10.1.0.32/28"<br>    ],<br>    "instance_type": "t3.micro",<br>    "name": "ingress2",<br>    "number_azs": 2,<br>    "public_subnet_cidrs": [<br>      "10.1.1.0/24",<br>      "10.1.2.0/24",<br>      "10.1.3.0/24"<br>    ],<br>    "tgw_subnet_cidrs": [<br>      "10.1.7.0/28",<br>      "10.1.7.16/28",<br>      "10.1.7.32/28"<br>    ],<br>    "workload_subnet_cidrs": [<br>      "10.1.4.0/24",<br>      "10.1.5.0/24",<br>      "10.1.6.0/24"<br>    ]<br>  }<br>}</pre> | no |
| <a name="input_secrets_names"></a> [secrets\_names](#input\_secrets\_names) | Secrets names - shared variable between AWS Accounts. | `map(string)` | <pre>{<br>  "firewall_manager": "firewall_manager_identifier",<br>  "spoke_vpc_information": "spoke_vpc_information",<br>  "transit_gateway": "transit_gateway_identifier"<br>}</pre> | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->