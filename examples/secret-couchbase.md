# Couchbase Secret Configuration Options

This benchmark will test the dynamic generation of Couchbase credentials. In order to use this test, configuration for the Couchbase instance must be provided as a JSON file using the `couchbase_config_json` flag. The primary required fields are the `username` and `password` for the user configured in Couchbase for Vault to use, as well as the `hosts` field that defines the addresses to use. A role configuration file can also be passed via the `couchbase_role_config_json` flag. This allows more specific options to be specified if required by the Couchbase environment setup.

## Test Parameters (minimum 1 required)

- `pct_couchbase_read`: percent of requests that are Couchbase dynamic credential generations

## Additional Parameters

- `couchbase_config_json` _(required)_: path to JSON file containing Vault CouchbaseDB configuration.  Configuration options can be found in the [CouchbaseDB Vault documentation](https://www.vaultproject.io/api-docs/secret/databases/couchbase#configure-connection).
- `couchbase_role_config_json`: path to a JSON file containing the CouchbaseDB role configuration. If this is not specified, a default configuration will be used (see below).

### Default CouchbaseDB Role Configuration

```json
{
 "default_ttl": "1h",
 "max_ttl": "24h",
 "creation_statements": "{\"Roles\": [{\"role\":\"ro_admin\"}]}"
}
```

### Example Usage

```bash
$ benchmark-vault -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_couchbase_read=100 \
    -couchbase_config_json=/path/to/couchbase/config.json
op                    count  rate       throughput  mean          95th%         99th%         successRatio
couchbase cred retrieval  687    68.602787  67.609274   146.945225ms  153.417724ms  176.005047ms  100.00%
```
