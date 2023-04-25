# Static Redis Secrets Engine Benchmark
This benchmark will test the static generation of redis credentials. In order to use this test, configuration for the target redis database must be provided as part of the configuration. 

## Test Parameters
### Database Configuration `db`
- `name` `(string: "benchmark-redis-db")` – Specifies the name for this database connection. This is specified as part of the URL.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified during initial configuration. Defaults to true.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `allowed_roles` `(list: ["my-*-role"])` - List of the roles allowed to use this connection. If contains a `*` any role can use this connection.
- `username` `(string: <required>)` – Specifies the username for Vault to use.
- `password` `(string: <required>)` – Specifies the password corresponding to the given username.
- `host` `(string: <required>)` – Specifies the host to connect to.
- `port` `(int: <required>)` – Specifies the port number of the connection.
- `tls` `(bool: false)` – Specifies whether to use TLS when connecting to Redis.
- `insecure_tls` `(bool: false)` – Specifies whether to skip verification of the
server certificate when using TLS.
- `ca_cert` _(string: optional)_: Specifies whether to use TLS when connecting to Redis.

### Static Role Config `role`
- `name` `(string: "my-static-role")` – Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` `(string: "benchmark-redis-db")` - The name of the database connection to use for this role.
- `rotation_period` `(string/int: "5m")` – Specifies the amount of time Vault should wait before rotating the password. The minimum is 5 seconds.
- `username` `(string: <required>)` – Specifies the database username that this Vault role corresponds to.

### Example vault-benchmark config map YAML
```hcl
test "redis_static_secret" "redis_static_secret_1" {
  weight = 100
  config {
    db {
      host          = "localhost"
      name          = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "default"
      password      = "pass"
      tls           = false
    }

    role {
      name            = "my-s-role"
      db_name         = "redis"
      rotation_period = "5m"
      username        = "my-static-role"
    }
  }
}
```

```bash
$ vault-benchmark run -config=config.hcl
2023-04-25T11:19:42.638-0500 [INFO]  vault-benchmark: setting up targets
2023-04-25T11:19:42.658-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-25T11:19:44.663-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op                     count  rate         throughput   mean        95th%       99th%        successRatio
redis_static_secret_1  4818   2408.666450  2404.376084  4.154177ms  4.843807ms  12.356863ms  100.00%
```
