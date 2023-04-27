# Userpass Auth Benchmark
This benchmark tests the performance of logins using the userpass auth method.

## Test Parameters
### Auth Configuration `config`
- `username` `(string: "benchmark-user")` – The username for the user. Accepted characters: alphanumeric plus "_", "-", "." (underscore, hyphen and period); username cannot begin with a hyphen, nor can it begin or end with a period.
- `password` `(string)` - The password for the user. Only required when creating the user.
- `token_ttl` `(string: "")` - The incremental lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_max_ttl` `(string: "")` - The maximum lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_policies` `(array: [])` - List of
  token policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.
- `token_bound_cidrs` `(array: [])` - List of
  CIDR blocks; if set, specifies blocks of IP addresses which can authenticate
  successfully, and ties the resulting token to these blocks as well.
- `token_explicit_max_ttl` `(integer: 0)` - If set, will encode
  an [explicit max
  TTL](/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token. This is a hard cap even if `token_ttl` and `token_max_ttl`
  would otherwise allow a renewal.
- `token_no_default_policy` `(bool: false)` - If set, the `default` policy will
  not be set on generated tokens; otherwise it will be added to the policies set
  in `token_policies`.
- `token_num_uses` `(integer: 0)` - The maximum number of times a generated
  token may be used (within its lifetime); 0 means unlimited.
  If you require the token to have the ability to create child tokens,
  you will need to set this value to 0.
- `token_period` `(integer: 0)` - The maximum allowed [period](/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) value when a periodic token is requested from this role.
- `token_type` `(string: "")` - The type of token that should be generated. Can
  be `service`, `batch`, or `default` to use the mount's tuned default (which
  unless changed will be `service` tokens). For token store roles, there are two
  additional possibilities: `default-service` and `default-batch` which specify
  the type to return unless the client requests a different type at generation
  time.

## Example HCL
```
test "userpass_auth" "userpass_test1" {
    weight = 100
    config {
        username = "test-user"
        password = "password"
    }
}
```

## Example Usage
```
$ vault-benchmark run -config=config.hcl
2023-04-27T08:25:52.436-0500 [INFO]  vault-benchmark: setting up targets
2023-04-27T08:25:52.558-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-27T08:25:54.638-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op              count  rate        throughput  mean         95th%        99th%         successRatio
userpass_test1  257    128.275142  123.740847  79.775804ms  99.824563ms  106.657676ms  100.00%
```




















## Test Parameters

### Userpass Config

- `username` _(string: benchmark-user)_: The username for the user. Accepted characters: alphanumeric plus "_", "-", "." (underscore, hyphen and period); username cannot begin with a hyphen, nor can it begin or end with a period.
- `password` _(string: <randomized>)_: The password for the user. Only required when creating the user.

## Example Configuration

```hcl
test "userpass_auth" "userpass_test_1" {
    weight = 100
    config {
        username = "benchmarkrole"
        password = "password"
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=example-configs/userpass/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op               count  rate        throughput  mean         95th%         99th%         successRatio
userpass_test_1  1086   108.598230  107.736705  92.408883ms  108.780321ms  124.803047ms  100.00%
```
