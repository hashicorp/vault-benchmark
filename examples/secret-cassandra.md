# CassandraDB Secret Configuration Options

This benchmark will test the dynamic generation of CassandraDB credentials. In order to use this test, configuration for the CassandraDB instance MUST be provided as a JSON file using the `cassandradb_config_json` flag. The primary required fields are the `username` and `password` for the user configured in CassandraDB for Vault to use, as well as the `hosts` field that defines the addresses to be use and the `protocol_version`.  A role configuration file can also be passed via the `cassandradb_role_config_json` flag. This allows more specific options to be specified if required by the CassandraDB environment setup.

## Test Parameters (minimum 1 required)

- `pct_cassandradb_read`: percent of requests that are CassandraDB Dynamic Credential generations

## Additional Parameters

- `cassandradb_config_json` _(required)_: path to JSON file containing Vault CassandraDB configuration.  Configuration options can be found in the [CassandraDB Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases/cassandra#configure-connection).  Example configuration files can be found in the [cassandradb configuration directory](/example-configs/cassandradb/).
- `cassandradb_role_config_json`: path to CassandraDB benchmark role configuration JSON file to use.  If this is not specified, a default configuration will be used (see below).

### Default CassandraDB Role Configuration

```json
{
 "default_ttl": "1h",
 "max_ttl": "24h",
 "creation_statements": "CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"
}
```

### Example Usage

```bash
$ benchmark-vault -pct_cassandradb_read=100 \
    -cassandradb_config_json=/path/to/cassandradb/config.json \
    -cassandradb_role_config_json=/path/to/cassandradb/role.json
op               count  rate       throughput  mean          95th%         99th%         successRatio
cassandra cred retrieval  1000   100.000000  0.000000    1.000000ms   1.000000ms   1.000000ms   0.00%
```
