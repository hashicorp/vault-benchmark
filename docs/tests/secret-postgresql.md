# Postgresql Secrets Engine Benchmark `postgresql_secret`

This benchmark will test the dynamic generation of PostgreSQL credentials.

## Example Configuration

```hcl
test "postgresql_secret" "postgres_test_1" {
    weight = 100
    config {
        db_connection {
            connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
            username = "username"
            password = "password"
        }

        role {
            creation_statements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-05-01T21:10:03.140-0500 [INFO]  vault-benchmark: setting up targets
2023-05-01T21:10:03.222-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-05-01T21:10:05.282-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op               count  rate        throughput  mean         95th%        99th%        successRatio
postgres_test_1  455    226.219503  220.930941  44.864053ms  63.980785ms  77.447877ms  100.00%
```

## Test Parameters

### DB Config `db_connection`

- `name` `(string: "benchmark-postgres")` – Specifies the name for this database
  connection. This is specified as part of the URL.
- `plugin_name` `(string: "postgresql-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin
  to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified
  during initial configuration. Defaults to true.
- `allowed_roles` `(list: [])` - List of the roles allowed to use this connection.
  Defaults to empty (no roles), if contains a `*` any role can use this connection.
- `root_rotation_statements` `(list: [])` - Specifies the database statements to be
  executed to rotate the root user's credentials. See the plugin's API page for more
  information on support and formatting for this parameter.
- `password_policy` `(string: "")` - The name of the
  [password policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies) to use when generating passwords for this database. If not specified, this will use a default policy defined as: 20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `connection_url` `(string)` - Specifies the connection string used to connect to the
  database. Some plugins use `url` rather than `connection_url`. This allows for simple templating of the username and password of the root user. Typically, this is done by including a `{{username}}`, `{{name}}`, and/or `{{password}}` field within the string. These fields are typically be replaced with the values in the `username` and `password` fields.
- `max_open_connections` `(int: 4)` - Specifies the maximum number of open
  connections to the database.
- `max_idle_connections` `(int: 0)` - Specifies the maximum number of idle
  connections to the database. A zero uses the value of `max_open_connections`
  and a negative value disables idle connections. If larger than
  `max_open_connections` it will be reduced to be equal.
- `max_connection_lifetime` `(string: "0s")` - Specifies the maximum amount of
  time a connection may be reused. If <= `0s`, connections are reused forever.
- `username` `(string: "")` - The root credential username used in the connection URL. This can also be provided via the `VAULT_BENCHMARK_POSTGRES_USERNAME` environment variable.
- `password` `(string: "")` - The root credential password used in the connection URL. This can also be provided via the `VAULT_BENCHMARK_POSTGRES_PASSWORD` environment variable.
- `username_template` `(string)` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how
  dynamic usernames are generated.
- `disable_escaping` `(boolean: false)` - Turns off the escaping of special characters inside of the username
  and password fields. See the [databases secrets engine docs](https://developer.hashicorp.com/vault/docs/secrets/databases#disable-character-escaping)
  for more information. Defaults to `false`.

### Role Config `role`

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This
  is specified as part of the URL.
- `db_name` `(string: "benchmark-postgres")` - The name of the database connection to use for this role.
- `default_ttl` `(string: "")` - Specifies the TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`).
  Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` - Specifies the maximum TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`).
  Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](https://developer.hashicorp.com/vault/docs/concepts/tokens#the-general-case).
  - `creation_statements` `(list: <required>)` – Specifies the database
  statements executed to create and configure a user. Must be a
  semicolon-separated string, a base64-encoded semicolon-separated string, a
  serialized JSON string array, or a base64-encoded serialized JSON string
  array. The `{{name}}`, `{{password}}` and `{{expiration}}` values will be
  substituted. The generated password will be a random alphanumeric 20 character
  string.
- `revocation_statements` `(list: [])` – Specifies the database statements to
  be executed to revoke a user. Must be a semicolon-separated string, a
  base64-encoded semicolon-separated string, a serialized JSON string array, or
  a base64-encoded serialized JSON string array. The `{{name}}` value will be
  substituted. If not provided defaults to a generic drop user statement.
- `rollback_statements` `(list: [])` – Specifies the database statements to be
  executed rollback a create operation in the event of an error. Not every
  plugin type will support this functionality. Must be a semicolon-separated
  string, a base64-encoded semicolon-separated string, a serialized JSON string
  array, or a base64-encoded serialized JSON string array. The `{{name}}` value
  will be substituted.
- `renew_statements` `(list: [])` – Specifies the database statements to be
  executed to renew a user. Not every plugin type will support this
  functionality. Must be a semicolon-separated string, a base64-encoded
  semicolon-separated string, a serialized JSON string array, or a
  base64-encoded serialized JSON string array. The `{{name}}` and
  `{{expiration}}` values will be substituted.
- `rotation_statements` `(list: [])` – Specifies the database statements to be
  executed to rotate the password for a given username. Must be a
  semicolon-separated string, a base64-encoded semicolon-separated string, a
  serialized JSON string array, or a base64-encoded serialized JSON string
  array. The `{{name}}` and `{{password}}` values will be substituted. The
  generated password will be a random alphanumeric 20 character string.
