# Cassandra Secrets Engine Benchmark (`cassandra_secret`)

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
- `allowed_roles` `(list: ["benchmark-role"])` - List of the roles allowed to use this connection.
  If contains a `*` any role can use this connection.
- `root_rotation_statements` `(list: [])` - Specifies the database statements to be
  executed to rotate the root user's credentials. See the plugin's API page for more
  information on support and formatting for this parameter.
- `password_policy` `(string: "")` - The name of the
  [password policy](https://developer.hashicorp.com/vault/api-docs/secret/databases) to use when generating passwords
  for this database. If not specified, this will use a default policy defined as:
  20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `hosts` `(string: <required>)` – Specifies a set of comma-delineated Cassandra
  hosts to connect to.
- `port` `(int: 9042)` – Specifies the default port to use if none is provided
  as part of the host URI. Defaults to Cassandra's default transport port, 9042.
- `protocol_version` `(int: 2)` – Specifies the CQL protocol version to use.
- `username` `(string: <required>)` – Specifies the username to use for
  superuser access. This can also be provided via the `VAULT_BENCHMARK_CASSANDRADB_USERNAME` environment variable.
- `password` `(string: <required>)` – Specifies the password corresponding to
  the given username. This can also be provided via the `VAULT_BENCHMARK_CASSANDRADB_PASSWORD` environment variable.
- `tls` `(bool: true)` – Specifies whether to use TLS when connecting to
  Cassandra.
- `insecure_tls` `(bool: false)` – Specifies whether to skip verification of the
  server certificate when using TLS.
- `pem_bundle` `(string: "")` – Specifies concatenated PEM blocks containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate.
- `skip_verification` `(bool: false)` - Skip permissions checks when a connection to Cassandra
  is first created. These checks ensure that Vault is able to create roles, but can be resource
  intensive in clusters with many roles.
- `connect_timeout` `(string: "5s")` – Specifies the timeout to use, both for
  connections and in general.
- `local_datacenter` `(string: "")` – If set, enables host selection policy
  which will prioritize and use hosts which are in the local datacenter before
  hosts in all other datacenters (for example `dc-01`).
- `socket_keep_alive` `(string: "0s")` – the keep-alive period for an active
  network connection. If zero, keep-alives are not enabled.
- `consistency` `(string: "")` – Specifies the consistency option to use. See
  the [gocql
  definition](https://github.com/gocql/gocql/blob/master/frame.go#L188) for
  valid options.
- `username_template` `(string: "")` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how dynamic usernames are generated.

~> We highly recommended that you use a Vault-specific user rather than the admin user
in your database when configuring the plugin. This user will be used to
create/update/delete users within the database so it will need to have the appropriate
permissions to do so.

### Role Configuration `role`

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` `(string: "benchmark-cassandra")` - The name of the database connection to use for this role.
- `default_ttl` `(string: "")` - Specifies the TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`). Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` - Specifies the maximum TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`). Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](https://developer.hashicorp.com/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(list: [])` – Specifies the database
  statements executed to create and configure a user. Must be a
  semicolon-separated string, a base64-encoded semicolon-separated string, a
  serialized JSON string array, or a base64-encoded serialized JSON string
  array. The `{{username}}` and `{{password}}` values will be substituted. If not
  provided, defaults to a generic create user statements that creates a
  non-superuser.
- `revocation_statements` `(list: [])` – Specifies the database statements to
  be executed to revoke a user. See the plugin's API page for more information
  on support and formatting for this parameter.
- `rollback_statements` `(list: [])` – Specifies the database statements to be
  executed to rollback a create operation in the event of an error. Not every
  plugin type will support this functionality. See the plugin's API page for
  more information on support and formatting for this parameter.

### Example HCL

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
            creation_statements = ["CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"]
        }
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-04-27T13:36:04.553-0500 [INFO]  vault-benchmark: setting up targets
2023-04-27T13:36:04.768-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-27T13:36:07.662-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op                  count  rate       throughput  mean         95th%         99th%      successRatio
cassandra_secret_1  34     16.635150  11.754942   739.57933ms  852.527624ms  859.465ms  100.00%
```
