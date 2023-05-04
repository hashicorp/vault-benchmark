# Couchbase Secrets Engine Benchmark `couchbase_secret`

This benchmark will test the dynamic generation of Couchbase credentials.

## Test Parameters

### DB Configuration `db_connection`

- `name` `(string: "benchmark-database")` – Specifies the name for this database
  connection. This is specified as part of the URL.
- `plugin_name` `(string: "couchbase-database-plugin")` - Specifies the name of the plugin to use
  for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin
  to use for this connection.
- `hosts` `(string: <required>)` – Specifies a set of comma-delimited Couchbase
  hosts to connect to. Must use `couchbases://` scheme if `tls` is `true`.
- `username` `(string: <required>)` – Specifies the username for Vault to use. This can also be provided via the `VAULT_BENCHMARK_COUCHBASE_USERNAME` environment variable.
- `password` `(string: <required>)` – Specifies the password corresponding to
  the given username. This can also be provided via the `VAULT_BENCHMARK_COUCHBASE_PASSWORD` environment variable.
- `tls` `(bool: false)` – Specifies whether to use TLS when connecting to
  Couchbase.
- `insecure_tls` `(bool: false)` – Specifies whether to skip verification of the
  server certificate when using TLS.
- `base64pem` `(string: "")` – Required if `tls` is `true`. Specifies the
  certificate authority of the Couchbase server, as a PEM certificate that has
  been base64 encoded.
- `bucket_name` `(string: "")` - Required for Couchbase versions prior to 6.5.0. This
  is only used to verify vault's connection to the server.
- `username_template` `(string: "")` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how dynamic usernames are generated.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified
  during initial configuration. Defaults to true.
- `allowed_roles` `(list: ["benchmark-role"])` - List of the roles allowed to use this connection.
  If contains a `*` any role can use this connection.
- `password_policy` `(string: "")` - The name of the
  [password policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies) to use when generating passwords
  for this database. If not specified, this will use a default policy defined as:
  20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `disable_escaping` `(boolean: false)` - Determines whether special characters in the
  username and password fields will be escaped. Useful for alternate connection string
  formats like ADO. More information regarding this parameter can be found on the
  [databases secrets engine docs.](https://developer.hashicorp.com/vault/docs/secrets/databases#disable-character-escaping)
  Defaults to `false`.

### Role Configuration `role`

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This
  is specified as part of the URL.
- `db_name` `(string: "benchmark-database")` - The name of the database connection to use
  for this role.
- `default_ttl` `(string: "")` - Specifies the TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`).
  Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` - Specifies the maximum TTL for the leases
 associated with this role. Accepts time suffixed strings (`1h`).
  Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](https://developer.hashicorp.com/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(list: [])` – Specifies the database
  statements executed to create and configure a user. Must be a
  semicolon-separated string, a base64-encoded semicolon-separated string, a
  serialized JSON string array, or a base64-encoded serialized JSON string
  array. The `{{username}}` and `{{password}}` values will be substituted. If not
  provided, defaults to a generic create user statements that creates a
  non-superuser.
- `revocation_statements` `(list: [])` – Specifies the database statements to
  be executed to revoke a user. Must be a semicolon-separated string, a
  base64-encoded semicolon-separated string, a serialized JSON string array, or
  a base64-encoded serialized JSON string array. The `{{username}}` value will be
  substituted. If not provided defaults to a generic drop user statement.
- `rollback_statements` `(list: [])` – Specifies the database statements to be
  executed to rollback a create operation in the event of an error. Must be a
  semicolon-separated string, a base64-encoded semicolon-separated string, a
  serialized JSON string array, or a base64-encoded serialized JSON string
  array. The `{{username}}` value will be substituted. If not provided, defaults to
  a generic drop user statement
- `root_rotation_statements` `(list: [])` - Specifies the database statements
  to be executed when rotating the root user's password. Must be a
  semicolon-separated string, a base64-encoded semicolon-separated string, a
  serialized JSON string array, or a base64-encoded serialized JSON string
  array. The `{{username}}` value will be substituted. If not provided, defaults to
  a reasonable default alter user statement.

### Example Configuration

```hcl
test "couchbase_secret" "couchbase_test_1" {
    weight = 100
    config {
        db_connection {
            username = "username"
            password = "password"
            hosts = "couchbase://127.0.0.1"
            bucket_name = "benchmark-vault"
        }

        role {
                default_ttl = "5m"
                max_ttl = "1h"
        }
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=config.hcl
Setting up targets...
Starting benchmarks. Will run for 1s...
Benchmark complete!
Target: http://127.0.0.1:8200
op                count  rate        throughput  mean         95th%         99th%         successRatio
couchbase_test_1  109    108.336919  100.456417  97.007399ms  151.364911ms  172.702436ms  100.00%
```
