# HCP Terraform Secrets Engine Benchmark (`terraform_secret`)

This benchmark will test the dynamic generation of HCP Terraform (Terraform Cloud) API tokens.

## Test Parameters

### Terraform Configuration `terraform`

- `address` `(string: "https://app.terraform.io")` – Specifies the address of the Terraform Cloud server. If using Terraform Enterprise, provide as `"protocol://host:port"`. The default is `https://app.terraform.io` for HCP Terraform. This can also be provided via the `VAULT_BENCHMARK_TERRAFORM_ADDRESS` environment variable.
- `token` `(string: "")` – Specifies the HCP Terraform authentication token to use. This token must have the needed permissions to manage all Organization, Team, and User tokens desired for this mount. This can also be provided via the `VAULT_BENCHMARK_TERRAFORM_TOKEN` environment variable.

### Role Configuration `role`

The HCP Terraform secrets engine role can operate in one of 3 modes based on credential type:

1. **Generate Organization API tokens** - set `organization` and `credential_type = "organization"`
2. **Generate Team API tokens** - set `team_id` and `credential_type = "team"`
3. **Generate User API tokens** - set `user_id` and `credential_type = "user"`

Note: Organizations can only have a single active API token at any given time. Generating a new token will revoke any existing tokens.

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create.
- `organization` `(string: "")` – Organization name to manage the single API token. Conflicts with `user_id` and `team_id`.
- `team_id` `(string: "")` – Team ID to manage API tokens. Conflicts with `user_id` and `organization`.
- `user_id` `(string: "")` – User ID to manage dynamic tokens. Conflicts with `organization` and `team_id`.
- `credential_type` `(string: "")` – Specifies the type of credential to generate. Valid values are `team`, `user`, or `organization`. If unspecified, Vault sets it automatically based on the type of ID provided.
- `description` `(string: "")` – Description of the role. Applies to User and Team API tokens. Used as a prefix to help identify the token in the HCP Terraform UI.
- `ttl` `(string: "")` – Specifies the TTL for this role. If not provided, the default Vault TTL is used. Applies to User and Team API tokens.
- `max_ttl` `(string: "")` – Specifies the max TTL for this role. If not provided, the default Vault Max TTL is used. Applies to User and Team API tokens.

## Example Configurations

### User API Token

```hcl
test "terraform_secret" "tf_user_test" {
    weight = 100
    config {
        terraform {
            address = "https://app.terraform.io"
            token = "your-terraform-api-token"
        }
        role {
            name = "benchmark-user-role"
            user_id = "user-1234567890abcdef"
            credential_type = "user"
            description = "Vault benchmark user role"
            ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```

### Organization API Token

```hcl
test "terraform_secret" "tf_org_test" {
    weight = 100
    config {
        terraform {
            address = "https://app.terraform.io"
            token = "your-terraform-api-token"
        }
        role {
            name = "benchmark-org-role"
            organization = "my-organization"
            credential_type = "organization"
            description = "Vault benchmark org role"
        }
    }
}
```

### Team API Token

```hcl
test "terraform_secret" "tf_team_test" {
    weight = 100
    config {
        terraform {
            address = "https://app.terraform.io"
            token = "your-terraform-api-token"
        }
        role {
            name = "benchmark-team-role"
            team_id = "team-1234567890abcdef"
            credential_type = "team"
            description = "Vault benchmark team role"
            ttl = "2h"
            max_ttl = "48h"
        }
    }
}
```

### Using Environment Variables

```hcl
test "terraform_secret" "tf_env_test" {
    weight = 100
    config {
        terraform {
            # address and token will be read from environment variables:
            # VAULT_BENCHMARK_TERRAFORM_ADDRESS
            # VAULT_BENCHMARK_TERRAFORM_TOKEN
        }
        role {
            name = "benchmark-env-role"
            user_id = "user-1234567890abcdef"
            credential_type = "user"
            description = "Vault benchmark with env vars"
            ttl = "30m"
            max_ttl = "12h"
        }
    }
}
```

### Terraform Enterprise

```hcl
test "terraform_secret" "tfe_test" {
    weight = 100
    config {
        terraform {
            address = "https://terraform.example.com"
            token = "your-tfe-api-token"
        }
        role {
            name = "benchmark-tfe-role"
            user_id = "user-1234567890abcdef"
            credential_type = "user"
            description = "Vault benchmark TFE role"
            ttl = "1h"
            max_ttl = "8h"
        }
    }
}
```

## Prerequisites

To use this benchmark test, you need:

1. **HCP Terraform Account**: A valid HCP Terraform (or Terraform Enterprise) account
2. **API Token**: A HCP Terraform API token with appropriate permissions
3. **User/Team/Organization IDs**: The specific IDs for the entities you want to generate tokens for

### Getting Required IDs

**User ID**: You can get your user ID by calling:
```bash
curl -s \
  --header "Authorization: Bearer $TF_TOKEN" \
  --header "Content-Type: application/vnd.api+json" \
  --request GET \
  https://app.terraform.io/api/v2/account/details | jq -r ".data.id"
```

**Team ID**: Available in HCP Terraform UI under Team settings or via API
**Organization Name**: Your organization name from HCP Terraform

## Environment Variables

- `VAULT_BENCHMARK_TERRAFORM_TOKEN` - HCP Terraform API token
- `VAULT_BENCHMARK_TERRAFORM_ADDRESS` - HCP Terraform server address (defaults to https://app.terraform.io)

Details about the configuration options can be found in the [HCP Terraform secrets engine (API) documentation](https://developer.hashicorp.com/vault/api-docs/secret/terraform).
