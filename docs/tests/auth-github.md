# GitHub Auth Benchmark (`github_auth`)

This benchmark will test GitHub Authentication to Vault. The primary required fields are `organization` and `token`.

## Test Parameters

### Auth Configuration `auth`

- `organization` `(string: <required>)` - The organization users must be part of.
- `organization_id` `(int: 0)` - The ID of the organization users must be part of. Vault will attempt to fetch and set this value if it is not provided.
- `base_url` `(string: "")` - The API endpoint to use. Useful if you are running GitHub Enterprise or an API-compatible authentication server.
- `token_ttl` `(string: "")` - The incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.
- `token_max_ttl` `(string: "")` - The maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.
- `token_policies` `(comma-delimited string: "")` - List of token policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.
- `policies` `(comma-delimited string: "")` - DEPRECATED: Please use the `token_policies` parameter instead. List of token policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.
- `token_bound_cidrs` `(comma-delimited string: "")` - List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.
- `token_explicit_max_ttl` `(string: "")` - If set, will encode an [explicit max TTL](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) onto the token. This is a hard cap even if `token_ttl` and `token_max_ttl` would otherwise allow a renewal.
- `token_no_default_policy` `(bool: false)` - If set, the `default` policy will not be set on generated tokens; otherwise it will be added to the policies set in `token_policies`.
- `token_num_uses` `(integer: 0)` - The maximum number of times a generated token may be used (within its lifetime); 0 means unlimited. If you require the token to have the ability to create child tokens, you will need to set this value to 0.
- `token_period` `(string: "")` - The maximum allowed [period](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) value when a periodic token is requested from this role.
- `token_type` `(string: "")` - The type of token that should be generated. Can be `service`, `batch`, or `default` to use the mount's tuned default (which unless changed will be `service` tokens). For token store roles, there are two additional possibilities: `default-service` and `default-batch` which specify the type to return unless the client requests a different type at generation time.

### Test User Config `test_user

- `token` `(string: <required>)` - GitHub personal API token.  This can also be provided via the `VAULT_BENCHMARK_GITHUB_TOKEN` environment variable.

## Example HCL

```hcl
test "github_auth" "github_auth1" {
    weight = 100
    config {
        auth {
            organization    = "Test-Organization"
            organization_id = "12345678910"
        }
        test_user  {
            token = $VAULT_BENCHMARK_GITHUB_TOKEN
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=github.hcl
2023-07-25T11:49:39.203-0400 [INFO]  vault-benchmark: setting up targets
2023-07-25T11:49:39.216-0400 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-07-25T11:49:42.359-0400 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op         count  rate       throughput  mean          95th%         99th%         successRatio
gh_auth_1  31     13.071887  9.864511    833.218959ms  994.991385ms  999.354042ms  100.00%
```
