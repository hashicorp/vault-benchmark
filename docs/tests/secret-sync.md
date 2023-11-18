# Secrets Sync Benchmark

This benchmark tests the performance of the secrets sync feature. 

## Test Parameters

### Configuration `config`

- `num_associations` `(int: 3)` - the number of associations to create. An association is the link that syncs one Vault 
secret as an external secret with one destination. For read and event-based test targets, the associations are created
during the setup phase. For write-based targets, the associations are created and updated as part of the load test.
- `destination_type` `(string: <required>)`:  The type of destination to sync the test secrets with, e.g. aw-sm. Refer to
the [Vault documentation](https://developer.hashicorp.com/vault/docs/sync) for the complete set of supported types.
- `destination_name` `(string: "benchmark-test-<UUID>")`:  The name of destination used to benchmark the sync operations.
- `destination_config` `(map<string|string>: <optional>)`:  The config to pass when creating the benchmark destination.
Refer to the [Vault documentation](https://developer.hashicorp.com/vault/docs/sync) or the examples below for the list 
of supported fields for each destination type.

## Example Configuration

```hcl
test "associations_write" "test_aws" {
  weight = 20
  config {
    num_associations = 50
    destination_type = "aws-sm"
    destination_name = "my-dest-1"
    destination_config = {
      access_key_id = "AKI..."
      secret_access_key = "j2m..."
      region = "us-east-2"
    }
  }
}

test "associations_write" "test_azure" {
  weight = 20
  config {
    num_associations = 50
    destination_type = "azure-kv"
    destination_name = "my-dest-2"
    destination_config = {
      key_vault_uri: "https://keyvault-1234.vault.azure.net",
      tenant_id: "<UUID>",
      client_id: "<UUID>",
      client_secret: "9Oy8..."
    }
  }
}

test "events" "test_gcp" {
  weight = 20
  config {
    num_associations = 50
    destination_type = "gcp-sm"
    destination_name = "my-dest-3"
    destination_config = {
        credentials = '@path/to/credentials.json'
    }
  }
}

test "associations_read" "test_github" {
  weight = 20
  config {
    num_associations = 1
    destination_type = "gh"
    destination_config = {
        access_token = "github_pat_1234"
        repository_owner = "hashicorp"
        repository_name = "vault-benchmark"
    }
  }
}

test "associations_read" "test_vercel" {
  weight = 20
  config {
    num_associations = 5
    destination_type = "vercel-project"
    destination_config = {
      access_token": "ujhM7...",
      project_id": "prj_1234",
      deployment_environments": ["development", "preview", "production"]
    }
  }
}
```
