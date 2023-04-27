# Consul Secret Benchmark

This benchmark will test the dynamic generation of Consul credentials.

## Test Parameters `config`
- `version` `(string: "1.14.0")`: Specifies the version of Consul. This is used to determine the correct API calls to make.

### Consul Config `consul`
- `address` `(string: <required>)`: Specifies the address of the Consul instance, provided as "host:port" like "127.0.0.1:8500"
- `token` `(string: "")`: Specifies the token to use for the Consul instance. This can also be provided via the `VAULT_BENCHMARK_CONSUL_TOKEN` environment variable.
- `scheme` `(string: "http")`: Specifies the URL scheme to use.

### Role Config `role`
- `name` `(string: "benchmark-role")`: Specifies the name of an existing role against which to create this Consul credential. This is part of the request URL.
- `token_type` `(string: "client")`: Specifies the type of token to create when using this role. Valid values are "client" or "management". If a "management" token, the policy parameter is not required. Defaults to "client".
- `local` `(bool: false)`: Indicates that the token should not be replicated globally and instead be local to the current datacenter. Only available in Consul 1.4 and greater.

## Example HCL
```hcl
test "consul_secret" "consul_test_1" {
    weight = 100
    config {
        version = "1.8.0"
        consul_config {
            address = "127.0.0.1:8500"
        }
        role_config {
            node_identities = [
                "client-1:dc1",
                "client-2:dc1"
            ]
        }
    }
}
```

## Example Usage
```bash
$ vault-benchmark run -config=example-configs/consul/config.hcl
2023-04-27T12:57:07.469-0500 [INFO]  vault-benchmark: setting up targets
2023-04-27T12:57:07.476-0500 [INFO]  vault-benchmark: starting benchmarks: duration=5s
2023-04-27T12:57:12.479-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op             count  rate         throughput   mean        95th%       99th%        successRatio
consul_test_1  12463  2492.488399  2491.245115  4.007578ms  6.123533ms  17.388957ms  100.00%
```
