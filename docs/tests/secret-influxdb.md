# InfluxDB Secrets Engine Benchmark (`influxdb_secret`)
This benchmark will test the dynamic generation of InfluxDB credentials.

⚠️ **Important**: This benchmark requires InfluxDB 1.x for compatibility with Vault's database secret engine.

~> We highly recommended that you use a Vault-specific user rather than the admin user
in your database when configuring the plugin. This user will be used to
create/update/delete users within the database so it will need to have the appropriate
permissions to do so.

## Benchmark Configuration Parameters

### DB Connection Configuration (`db_connection`)

- `name` `(string: "benchmark-influxdb")` - Name for this database connection. This is specified as part of the URL.
- `plugin_name` `(string: "influxdb-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` - Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` `(list: ["benchmark-role"])` - List of the roles allowed to use this connection.
- `root_rotation_statements` `(list: [])` - Specifies the database statements to be executed to rotate the root user's credentials.
- `password_policy` `(string: "")` - The name of the [password policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies) to use when generating passwords for this database. If not specified, this will use a default policy defined as: 20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `host` `(string: "localhost")` - Specifies the host to connect to.
- `port` `(int: 8086)` - Specifies the port to connect to.
- `username` `(string: <required>)` - Specifies the username for Vault to use. This can also be provided via the `VAULT_BENCHMARK_INFLUXDB_USERNAME` environment variable.
- `password` `(string: <required>)` - Specifies the password corresponding to the given username. This can also be provided via the `VAULT_BENCHMARK_INFLUXDB_PASSWORD` environment variable.
- `tls` `(bool: false)` - Whether to use TLS when connecting to InfluxDB.
- `insecure_tls` `(bool: false)` - Whether to skip verification of the server certificate when using TLS.
- `connect_timeout` `(string: "5s")` - The connection timeout to use.
- `username_template` `(string: "")` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how dynamic usernames are generated.

### Role Configuration (`role`)

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` `(string: "benchmark-influxdb")` - The name of the database connection to use for this role.
- `default_ttl` `(string: "1h")` – Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (`1h`) or an integer number of seconds. Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer.
- `max_ttl` `(string: "24h")` – Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (`1h`) or an integer number of seconds. Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer.
- `creation_statements` `(string: <required>)` – Specifies the database statements executed to create and configure a user. Must be a semicolon-separated string, a base64-encoded semicolon-separated string, a serialized JSON string array, or a base64-encoded serialized JSON string array. The `{{name}}` and `{{password}}` values will be substituted.
- `revocation_statements` `(string: "")` – Specifies the database statements to be executed to revoke a user. Must be a semicolon-separated string, a base64-encoded semicolon-separated string, a serialized JSON string array, or a base64-encoded serialized JSON string array. The `{{name}}` value will be substituted.
- `rollback_statements` `(string: "")` – Specifies the database statements to be executed to rollback a create operation in the event of an error. Not every plugin type will support this functionality.
- `renew_statements` `(string: "")` – Specifies the database statements to be executed to renew a user. Not every plugin type will support this functionality.

## Example HCL

```hcl
test "influxdb_secret" "influxdb_test_1" {
    weight = 100
    config {
        db_connection {
            host = "localhost"
            port = 8086
            username = "admin"
            password = "password"
            tls = false
        }
        role {
            creation_statements = "CREATE USER \"{{name}}\" WITH PASSWORD '{{password}}'; GRANT ALL ON \"mydb\" TO \"{{name}}\";"
            revocation_statements = "DROP USER \"{{name}}\";"
        }
    }
}
```
