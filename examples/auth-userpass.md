# Userpass Auth Configuration Options

This benchmark tests the performance of logins using the userpass auth method.

## Test Parameters

### Userpass Config

- `username` _(string: <required>)_: The username for the user. Accepted characters: alphanumeric plus "_", "-", "." (underscore, hyphen and period); username cannot begin with a hyphen, nor can it begin or end with a period.
- `password` _(string: <required>)_: The password for the user. Only required when creating the user.

### Role Config

- `name` _(string: "benchmark-role")_: Specifies the name of an existing role against which to create this Consul credential. This is part of the request URL.
- `token_type` _(string: "client") - Specifies the type of token to create when using this role. Valid values are "client" or "management". If a "management" token, the policy parameter is not required. Defaults to "client".
- `local` _(bool: false)_: Indicates that the token should not be replicated globally and instead be local to the current datacenter. Only available in Consul 1.4 and greater.

## Example Configuration

```hcl
test "userpass_auth" "userpass_test_1" {
    weight = 100
    config {
        role_config {
            username = "benchmarkrole"
            password = "password"
        }
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=example-configs/consul/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op               count  rate        throughput  mean         95th%         99th%         successRatio
userpass_test_1  1086   108.598230  107.736705  92.408883ms  108.780321ms  124.803047ms  100.00%
```
