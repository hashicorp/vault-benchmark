# Consul Secret Configuration Options

This benchmark will test the dynamic generation of Consul credentials.

## Test Parameters

### Consul Config

- `address` _(string: <required>)_: Specifies the address of the Consul instance, provided as "host:port" like "127.0.0.1:8500"
- `token` _(string: <required>)_: Specifies the token to use for the Consul instance. This can either be provided as a string or as the environment variable `$CONSUL_TOKEN`.
- `version` _(string: "1.14.0")_: Specifies the version of Consul. This is used to determine the correct API calls to make.
- `scheme` _(string: "http")_: Specifies the URL scheme to use.

### Role Config

- `name` _(string: "benchmark-role")_: Specifies the name of an existing role against which to create this Consul credential. This is part of the request URL.
- `token_type` _(string: "client") - Specifies the type of token to create when using this role. Valid values are "client" or "management". If a "management" token, the policy parameter is not required. Defaults to "client".
- `local` _(bool: false)_: Indicates that the token should not be replicated globally and instead be local to the current datacenter. Only available in Consul 1.4 and greater.

## Example Configuration

```hcl
test "consul_secret" "consul_test_1" {
    weight = 100
    config {
        consul_config {
            address = "127.0.0.1:8500"
            version = "1.8.0"
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
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op             count  rate        throughput  mean         95th%        99th%        successRatio
consul_test_1  3464   346.330155  345.885039  28.871437ms  44.718062ms  53.077136ms  100.00%
```
