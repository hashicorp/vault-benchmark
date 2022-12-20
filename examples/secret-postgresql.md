# PostgreSQL Secret Configuration Options

This benchmark will test the dynamic generation of PostgreSQL credentials. In order to use this test, configuration for the PostgreSQL instance must be provided as a JSON file using the `postgresql_config_json` flag. The primary required fields are the `username` and `password` for the user configured in PostgreSQL for Vault to use, as well as the `connection_url` field that defines the address to be used as well as any other parameters that need to be passed via the URL. A role configuration file can also be passed via the `postgresql_role_config_json` flag. This allows more specific options to be specified if required by the PostgreSQL environment setup.

## Test Parameters (minimum 1 required)

- `pct_postgresql_read`: percent of requests that are PostgreSQL credential generations

## Additional Parameters

- `postgresql_config_json` _(required)_: path to JSON file containing Vault PostgreSQL configuration.  Configuration options can be found in the [PostgreSQL Vault documentation](https://www.vaultproject.io/api-docs/secret/databases/postgresql#configure-connection).  Example configuration files can be found in the [postgresql configuration directory](/configs/postgresql/).
- `postgresql_role_config_json`: path to a JSON file containing the PostgreSQL role configuration. If this is not specified, a default configuration will be used (see below).

### Default PostgreSQL Role Configuration

```json
{
 "default_ttl": "1h",
 "max_ttl": "24h",
 "creation_statements": "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
}
```

### Example Usage

```bash
$ benchmark-vault \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_postgresql_read=100 \
    -postgresql_config_json=/path/to/postgresql/config.json
op                    count  rate       throughput  mean          95th%         99th%         successRatio
postgresql cred retrieval  1000   100.000000  0.000000    1.000000ms   1.000000ms   1.000000ms   0.00%
```
