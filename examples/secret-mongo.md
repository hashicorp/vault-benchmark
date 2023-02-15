# MongoDB Secret Configuration Options

This benchmark will test the dynamic generation of MongoDB credentials. In order to use this test, configuration for the MongoDB instance MUST be provided as a JSON file using the `mongodb_config_json` flag. The primary required fields are the `username` and `password` for the user configured in MongoDB for Vault to use, as well as the `connection_url` field that defines the address to be used. A role configuration file can also be passed via the `mongodb_role_config_json` flag. This allows more specific options to be specified if required by the MongoDB environment setup.

## Test Parameters (minimum 1 required)

- `pct_mongodb_read`: percent of requests that are MongoDB Dynamic Credential generations

## Additional Parameters

- `mongodb_config_json` _(required)_: path to JSON file containing Vault MongoDB configuration.  Configuration options can be found in the [MongoDB Vault documentation](https://www.vaultproject.io/api-docs/secret/databases/mongodb#configure-connection).  Example configuration files can be found in the [mongodb configuration directory](/configs/mongodb/).
- `mongodb_role_config_json`: path to a JSON file containing the MongoDB role configuration. If this is not specified, a default configuration will be used (see below).

### Default MongoDB Role Configuration

```json
{
    "db_name": "mongo-benchmark-database",
    "creation_statements": "{ \"db\": \"admin\", \"roles\": [{ \"role\": \"readWrite\" }, {\"role\": \"read\", \"db\": \"foo\"}] }",
    "default_ttl": "1h",
    "max_ttl": "24h"
}
```

### Example Usage

```bash
$ vault-benchmark \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_mongodb_read=100 \
    -mongodb_config_json=/path/to/mongodb/config.json
op                    count  rate       throughput  mean          95th%         99th%         successRatio
mongo cred retrieval  687    68.602787  67.609274   146.945225ms  153.417724ms  176.005047ms  100.00%
```
