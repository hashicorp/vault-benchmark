# Elasticsearch Secret Configuration Options
This benchmark will test the dynamic generation of Elasticsearch credentials. In order to use this test, configuration for the Elasticsearch instance MUST be provided as a JSON file using the `elasticsearch_db_config` flag. The primary required fields are the `username` and `password` for the user configured in elsaticsearch for Vault to use, as well as the `url` field that defines the Elasticsearch address to be used. A role configuration file can also be passed via the `elasticsearch_role_config` flag. This allows more specific options to be specified if required by the Elasticsearch environment setup.

## Test Parameters (minimum 1 required)
- `pct_elasticsearch_read`: percent of requests that are Elasticsearch Dynamic Credential generations

## Additional Parameters
- `elasticsearch_db_config` _(required)_: path to JSON file containing Vault Elasticsearch configuration.  Configuration options can be found in the [Elasticsearch Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases/elasticdb).  Example configuration files can be found in the [Elasticsearch configuration directory](/configs/elasticsearch/).
- `elasticsearch_role_config`: path to a JSON file containing the Elasticsearch role configuration. If this is not specified, a default configuration will be used (see below).

### Default Elasticsearch Role Configuration
```json
{
    "role_name": "my-vault-role",
    "creation_statements": "{\"elasticsearch_role_definition\": {\"indices\": [{\"names\":[\"*\"], \"privileges\":[\"read\"]}]}}",
    "default_ttl": "1h",
    "max_ttl": "24h"
}
```

### Example Usage

```bash
$ benchmark-vault \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_elasticsearch_read=100 \
    -elasticsearch_role_config=elasticsearch_role_config.json

Starting benchmark tests. Will run for 10s...
Benchmark complete!
Cleaning up...
op                  count  rate       throughput  mean          95th%         99th%         successRatio
elasticsearch read  316    31.437367  30.741718   319.975537ms  417.664574ms  546.783011ms  100.00%
```
