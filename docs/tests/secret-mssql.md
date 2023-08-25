# MSSQL Secret Benchmark (`mssql_secret`)

This benchmark will test the dynamic generation of MSSQL credentials.

## Test Parameters

### DB Connection Configuration `db_connection`

- `name` `(string: "benchmark-mssql")` - Name for this database connection. This is specified as part of the URL.
- `plugin_name` `(string: "mssql-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` - Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` `(list: ["benchmark_role"])` - List of the roles allowed to use this connection.
- `root_rotation_statements` `(list: [])` - Specifies the database statements to be executed to rotate the root user's credentials.
- `password_policy` `(string: "")` - The name of the password policy to use when generating passwords for this database. If not specified, this will use a default policy defined as: 20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `connection_url` `(string: <required>)` - Specifies the MSSQL DSN. This field can be templated and supports passing the username and password parameters in the following format `{{field_name}}`. A templated connection URL is required when using root credential rotation.
- `disable_escaping` `(boolean: false)` - Turns off the escaping of special characters inside of the username and password fields. See the [databases secrets engine docs](https://developer.hashicorp.com/vault/docs/secrets/databases#disable-character-escaping) for more information. Defaults to `false`.
- `contained_db` `(bool: false)` - If set, specifies that the connection being configured is to a [Contained Database](https://docs.microsoft.com/en-us/sql/relational-databases/databases/contained-databases?view=sql-server-ver15), like AzureSQL.
- `max_open_connections` `(int: 4)` - Specifies the maximum number of open connections to the database.
- `max_idle_connections` `(int: 0)` - Specifies the maximum number of idle connections to the database. A zero uses the value of `max_open_connections` and a negative value disables idle connections. If larger than `max_open_connections` it will be reduced to be equal.
- `max_connection_lifetime` `(string: "0s")` - Specifies the maximum amount of time a connection may be reused. If <= `0s` connections are reused forever.
- `username` `(string: <required>)` - The root credential username used in the connection URL. Can also be set using the `VAULT_BENCHMARK_MSSQL_USERNAME` environment variable.
- `password` `(string: <required>)` - The root credential password used in the connection URL. Can also be set using the `VAULT_BENCHMARK_MSSQL_PASSWORD` environment variable.
- `username_template` `(string: "")` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how dynamic usernames are generated.

### Role Configuration `role`

- `name` `(string: "benchmark-role")` - Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` `(string: "benchmark-mssql")` - The name of the database connection to use for this role.
- `default_ttl` `(string: "")` - Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (`1h`). Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` - Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (`1h`). Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](https://developer.hashicorp.com/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(list: <required>)` – Specifies the database  statements executed to create and configure a user. Must be a semicolon-separated string, a base64-encoded semicolon-separated string, a serialized JSON string array, or a base64-encoded serialized JSON string array. The `{{name}}` and `{{password}}` values will be substituted.
- `revocation_statements` `(list: [])` – Specifies the database statements to be executed to revoke a user. Must be a semicolon-separated string, a base64-encoded semicolon-separated string, a serialized JSON string array, or a base64-encoded serialized JSON string array. The `{{name}}` value will be substituted. If not provided defaults to a generic drop user statement.

## Example Configuration

```hcl
test "mssql_secret" "mssql_test_1" {
    weight = 100
    config {
        db_connection {
            connection_url = "sqlserver://{{username}}:{{password}}@localhost:1433"
            username = "username"
            password = "P@$$word123"
        }

        role {
            creation_statements = "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}'; CREATE USER [{{name}}] FOR LOGIN [{{name}}]; GRANT SELECT ON SCHEMA::dbo TO [{{name}}];"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-04-27T20:22:44.803-0400 [INFO]  vault-benchmark: setting up targets
2023-04-27T20:22:44.858-0400 [INFO]  vault-benchmark: starting benchmarks: duration=1s
2023-04-27T20:22:45.981-0400 [INFO]  vault-benchmark: cleaning up targets
2023-04-27T20:22:50.774-0400 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op              count  rate       throughput  mean          95th%         99th%         successRatio
mssql_secret_1  94     93.214668  83.761150   114.236245ms  187.749698ms  188.590625ms  100.00%
```
