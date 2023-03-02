# Consul Secret Configuration Options

This benchmark will test Consul secret engine operations. In order to use this test, configuration for the Consul server must be provided as an HCL file using the `consul_config` body.  A `role_config` can also be provided.  The primary required field is `address` which is the address of the Consul server. Additionally, the Consul version should be in the `version` field, which is used to determine the correct API calls to make. The default version is `1.8.0`. The Consul server must be running and accessible from the Vault server.  The configuration options can be found in the [Consul Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/consul#configure-connection).  Example configuration files can be found in the [Consul configuration directory](/example-configs/consul/).

## Example Usage

```bash
benchmark-vault run -config=example-configs/consul/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op             count  rate        throughput  mean         95th%        99th%        successRatio
consul_test_1  3464   346.330155  345.885039  28.871437ms  44.718062ms  53.077136ms  100.00%
```
