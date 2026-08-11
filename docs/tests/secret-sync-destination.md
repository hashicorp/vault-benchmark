# Secrets Sync Destination Creation Benchmark

This benchmark tests the performance of creating secrets sync destinations. This test focuses exclusively on destination creation operations and does not create secrets, associations, or KV mounts.

## Test Parameters

### Configuration `config`

- `num_destinations` `(int: 3)` - This parameter is not used in the current implementation. All requests create/update the same destination.
- `destination_type` `(string: <required>)` - The type of destination to create, e.g. `aws-sm`, `azure-kv`, `gcp-sm`, etc. Refer to the [Vault documentation](https://developer.hashicorp.com/vault/docs/sync) for the complete set of supported types.
- `destination_name` `(string: "benchmark-test-<UUID>")` - The name of the destination to create during the benchmark. This must match the destination configured in your cloud provider for WIF (Workload Identity Federation) to work correctly.
- `destination_config` `(map<string|string>: <optional>)` - The configuration to pass when creating the benchmark destination. Refer to the [Vault documentation](https://developer.hashicorp.com/vault/docs/sync) or the examples below for the list of supported fields for each destination type.

## Example Configuration

```hcl
test "destination_create" "test_aws" {
  weight = 20
  config {
    num_destinations = 50
    destination_type = "aws-sm"
    destination_name = "my-dest-aws"
    destination_config = {
      access_key_id = "AKI..."
      secret_access_key = "j2m..."
      region = "us-east-2"
    }
  }
}

test "destination_create" "test_azure" {
  weight = 20
  config {
    num_destinations = 50
    destination_type = "azure-kv"
    destination_name = "my-dest-azure"
    destination_config = {
      key_vault_uri = "https://keyvault-1234.vault.azure.net"
      tenant_id = "<UUID>"
      client_id = "<UUID>"
      client_secret = "9Oy8..."
    }
  }
}

test "destination_create" "test_gcp" {
  weight = 20
  config {
    num_destinations = 30
    destination_type = "gcp-sm"
    destination_name = "my-dest-gcp"
    destination_config = {
      credentials = "@/path/to/credentials.json"
    }
  }
}

test "destination_create" "test_github" {
  weight = 20
  config {
    num_destinations = 10
    destination_type = "gh"
    destination_name = "my-dest-github"
    destination_config = {
      access_token = "github_pat_1234"
      repository_owner = "hashicorp"
      repository_name = "vault-benchmark"
    }
  }
}

test "destination_create" "test_vercel" {
  weight = 20
  config {
    num_destinations = 20
    destination_type = "vercel-project"
    destination_name = "my-dest-vercel"
    destination_config = {
      access_token = "ujhM7..."
      project_id = "prj_1234"
      deployment_environments = "[\"development\", \"preview\", \"production\"]"
    }
  }
}
```

## Notes

- This test performs **only destination creation** operations. It does not create KV mounts, secrets, or associations.
- During setup, no resources are pre-created.
- During the benchmark, each request creates/updates the same destination specified by `destination_name`.
- During cleanup, the destination created during the benchmark is deleted.
- The destination name must match the configuration in your cloud provider (Azure, AWS, GCP, etc.) for WIF (Workload Identity Federation) authentication to work correctly.
