# Cassandra Secrets Engine Benchmark
This benchmark will test the dynamic generation of Cassandra credentials.

## Test Parameters
### DB Connection Configuration `db_connection`
- `name` `(string: "benchmark-cassandra")` – Specifies the name for this database connection. This is specified as part of the URL.
- `plugin_name` `(string: "cassandra-database-plugin")` - Specifies the name of the plugin to use
  for this connection.
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
  [password policy](/vault/docs/concepts/password-policies) to use when generating passwords
  for this database. If not specified, this will use a default policy defined as:
  20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.

~> We highly recommended that you use a Vault-specific user rather than the admin user
in your database when configuring the plugin. This user will be used to
create/update/delete users within the database so it will need to have the appropriate
permissions to do so. If the plugin supports
[rotating the root credentials](#rotate-root-credentials), we highly recommended
you perform that action after configuring the plugin. This will change the password
of the user configured in this step. The new password will **not** be viewable by users.

### Role Configuration `role`






















## Example Configuration 
### Only HCL
```hcl
test "cassandra_secret" "cassandra_secret_1" {
    weight = 100
    config {
        db_connection {
            hosts =  "127.0.0.1"
            username = "cassandra"
            password = "cassandra"
            protocol_version = "3"
        }

        role {
            creation_statements = "CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"
        }
    }
}
```

```bash
$ vault-benchmark run -config=example-configs/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate        throughput  mean         95th%        99th%        successRatio
cassandra_test_1  249    248.880537  239.605824  41.018154ms  52.821772ms  58.667201ms  100.00%
```
