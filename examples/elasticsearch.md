# Elasticsearch Secret Configuration Options

This benchmark will test the dynamic generation of elasticsearch credentials. In order to use this test, configuration for the elasticsearch instance MUST be provided as a JSON file using the `elasticsearch_db_config` flag. The primary required fields are the `username` and `password` for the user configured in elsaticsearch for Vault to use, as well as the `url` field that defines the elasticsearch address to be used. A role configuration file can also be passed via the `elasticsearch_role_config` flag. This allows more specific options to be specified if required by the elasticsearch environment setup.

## Test Parameters (minimum 1 required)

- `pct_elasticsearch_read`: percent of requests that are MongoDB Dynamic Credential generations

## Additional Parameters

- `elasticsearch_db_config` _(required)_: path to JSON file containing Vault MongoDB configuration.  Configuration options can be found in the [Elastic Search Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases/elasticdb).  Example configuration files can be found in the [elasticsearch configuration directory](/configs/elasticsearch/).
- `elasticsearch_role_config`: path to a JSON file containing the elasticsearch role configuration. If this is not specified, a default configuration will be used (see below).

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
    -pct_mongodb_read=100 \
    -mongodb_config_json=/path/to/mongodb/config.json
op                    count  rate       throughput  mean          95th%         99th%         successRatio
mongo cred retrieval  687    68.602787  67.609274   146.945225ms  153.417724ms  176.005047ms  100.00%
```
