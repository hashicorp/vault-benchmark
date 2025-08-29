# Okta Auth Benchmark (`okta_auth`)

This benchmark will test Okta Authentication to Vault. The primary required fields are `org_name`, `username`, and `password`.

## Test Parameters

### Auth Configuration `auth`

- `org_name` `(string: <required>)` - The Okta organization name (e.g., "trial-2805164-admin" for trial-2805164-admin.okta.com).
- `api_token` `(string: <optional>)` - The Okta API token for enhanced functionality. If not provided, only basic authentication is performed.
- `base_url` `(string: "okta.com")` - The base URL for your Okta org. Use "oktapreview.com" for preview orgs.
- `bypass_okta_mfa` `(bool: false)` - Whether to bypass Okta MFA requirements during authentication.
- `token_ttl` `(string: "")` - The incremental lifetime for generated tokens.
- `token_max_ttl` `(string: "")` - The maximum lifetime for generated tokens.
- `token_policies` `(array: [])` - List of token policies to encode onto generated tokens.
- `policies` `(array: [])` - DEPRECATED: Please use the `token_policies` parameter instead.
- `token_bound_cidrs` `(array: [])` - List of CIDR blocks for IP address restrictions.
- `token_explicit_max_ttl` `(string: "")` - Hard cap on token lifetime.
- `token_no_default_policy` `(bool: false)` - Whether to exclude the default policy.
- `token_num_uses` `(integer: 0)` - Maximum number of times a token may be used.
- `token_period` `(string: "")` - Maximum period value for periodic tokens.
- `token_type` `(string: "")` - Type of token to generate (service, batch, default).

### Test User Configuration `test_user`

- `username` `(string: <required>)` - The Okta username to authenticate with.
- `password` `(string: <required>)` - The password for the Okta user.
- `groups` `(array: <optional>)` - List of Okta groups the user belongs to.
- `policies` `(array: <optional>)` - List of Vault policies to assign to the user.

## Example HCL (Fixed Configuration)

```hcl
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "30s"
cleanup = true

test "okta_auth" "okta_test_1" {
    weight = 100
    config {
        auth {
            org_name = "test-org"
            api_token = "00c6Px86XKYiwYxmVbCGZBWXPl2e1qZ6S8wAxcJlL9"
            base_url = "okta.com"
            bypass_okta_mfa = true
            token_ttl = "1h"
            token_max_ttl = "24h"
            token_policies = ["default"]
            token_bound_cidrs = []
            token_no_default_policy = false
            token_num_uses = 0
            token_period = "0"
            token_type = "default"
        }
        test_user {
            username = "admin@test-org.okta.com"
            password = "YourActualPassword"
            groups = ["Everyone"]
            policies = ["default","dev-policy"]
        }
    }
}
```
## Example Usage
```bash
$ vault-benchmark run -config=config.hcl
2025-08-29T15:11:36.948+0530 [INFO]  vault-benchmark: setting up targets
2025-08-29T15:11:36.951+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-08-29T15:11:47.576+0530 [INFO]  vault-benchmark: cleaning up targets
2025-08-29T15:11:47.602+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op           count  rate       throughput  mean          95th%         99th%         successRatio
okta_test_1  157    15.627254  14.776024   664.464399ms  1.236091504s  1.422604122s  100.00%
```

