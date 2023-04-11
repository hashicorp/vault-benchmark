# Cassandra Secret Configuration Options

This benchmark will test the dynamic generation of Cassandra credentials.

## Test Parameters
### DB Config
- `name` _(string: "benchmark-cassandra")_: Name for this database connection. This is specified as part of the URL.
- `plugin_name` _(string: "cassandra-database-plugin")_ - Specifies the name of the plugin to use for this connection.
- `hosts` _(string: <required>)_ – Specifies a set of comma-delineated Cassandra hosts to connect to.
- `port` _(int: 9042)_ – Specifies the default port to use if none is provided as part of the host URI. Defaults to Cassandra's default transport port, 9042.
- `protocol_version` _(int: 2)_ – Specifies the CQL protocol version to use.
- `username` _(string: <required>)_: The root credential username used in the connection URL.
- `password` _(string: <required>)_: The root credential password used in the connection URL.
- `allowed_roles` _(list: ["benchmark_role"])_: List of the roles allowed to use this connection. 
- `tls` _(bool: true)_ – Specifies whether to use TLS when connecting to Cassandra.
- `insecure_tls` _(bool: false)_ – Specifies whether to skip verification of the server certificate when using TLS.
- `tls_server_name` _(string: "")_ – Specifies the name to use as the SNI host when connecting to the Cassandra server via TLS.
- `pem_bundle` _(string: "")_ – Specifies concatenated PEM blocks containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate. Only one of pem_bundle or pem_json can be specified.
- `skip_verification` _(bool: false)_ - Skip permissions checks when a connection to Cassandra is first created. These checks ensure that Vault is able to create roles, but can be resource intensive in clusters with many roles.
- `connect_timeout` _(string: "5s")_ – Specifies the timeout to use, both for connections and in general.
- `local_data_center` _(string: "")_ – If set, enables host selection policy which will prioritize and use hosts which are in the local datacenter before hosts in all other datacenters (for example dc-01).
- `socket_keep_alive` _(string: "0s")_ – the keep-alive period for an active network connection. If zero, keep-alives are not enabled.
- `consistency` _(string: "")_ – Specifies the consistency option to use.
- `username_template` _(string)_ - Template describing how dynamic usernames are generated.

### Role Config
- `name` _(string: "benchmark-role")_: Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` _(string: "benchmark-cassandra")_: The name of the database connection to use for this role.
- `default_ttl` _(string/int: 0)_ - Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds. Defaults to system/engine default TTL time.
- `max_ttl` _(string/int: 0)_ - Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds. Defaults to sys/mounts's default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer.
- `creation_statements` _(string: <required>)_ – Specifies the database statements executed to create and configure a user. See the plugin's API page for more information on support and formatting for this parameter.
- `revocation_statements` _(string)_ – Specifies the database statements to be executed to revoke a user. See the plugin's API page for more information on support and formatting for this parameter.
- `rollback_statements` _(string)_ - Specifies the database statements to be executed to rollback a create operation in the event of an error. Not every plugin type will support this functionality. See the plugin's API page for more information on support and formatting for this parameter.

## Example Configuration 
### Only HCL
```hcl
test "cassandra_secret" "cassandra_secret_1" {
    weight = 100
    config {
        db {
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
