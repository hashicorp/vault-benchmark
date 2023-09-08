# Vault Benchmark

`vault-benchmark` has two subcommands, `run` and `review`. The `run` command is the main command used to execute a benchmark run using the provided benchmark test configuration. Configuration is provided as an HCL formatted file containing the desired global configuration options for `vault-benchmark` itself as well as the test definitions and their respective configuration options.

## Example Config

```hcl

# Global vault-benchmark config options

vault_addr = \"<http://127.0.0.1:8200>\"
vault_token = \"root\"
vault_namespace=\"root\"
duration = \"2s\"
report_mode = \"terse\"
random_mounts = true
cleanup = true

# Test definitions and configuration

test \"approle_auth\" \"approle_auth_test1\" {
    weight = 100
    config {
        role {
            role_name = \"benchmark-role\"
            token_ttl=\"2m\"
        }
    }
}
```

## Subcommands

- [Run](commands/run.md)
- [Review](commands/review.md)

## Benchmark Tests

Below is a list of all currently available benchmark tests
{{test_lists_placeholder}}

## Global Configuration Options

- [Global Configuration Options](global-configs.md)
