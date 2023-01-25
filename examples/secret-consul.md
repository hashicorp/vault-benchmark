# Consul Secret Configuration Options

This benchmark will test Consul secret engine operations. In order to use this test, configuration for the Consul server must be provided as a JSON file using the `consul_config_json` flag. The primary required field is `address` which is the address of the Consul server. Additionally, the Consul version should be in the `version` field, which is used to determine the correct API calls to make. The default version is `1.8.0`. The Consul server must be running and accessible from the Vault server.

## Test Parameters (minimum 1 required)

- `pct_consul_read`: percent of requests that are Consul Dynamic Credential generations

## Additional Parameters

- `consul_config_json` _(required)_: path to JSON file containing Vault Consul configuration.  The configuration options can be found in the [Consul Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/consul#configure-connection).  Example configuration files can be found in the [Consul configuration directory](/configs/consul/).
- `consul_role_config_json` _(required)_: path to a JSON file containing the Consul role configuration.  The configuration options can be found in the [Consul Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/consul#create-update-role).  Example configuration files can be found in the [Consul configuration directory](/configs/consul/).

### Example Usage

```bash
benchmark-vault \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_consul_read=100 \
    -consul_config_json=/path/to/consul/config.json \
    -consul_role_config_json=/path/to/consul/role/config.json

op                     count  rate        throughput  mean         95th%       99th%       successRatio
consul cred retrieval  16333  505.071903  0.000000    19.796727ms  2.039453ms  3.982598ms  0.00%
```
