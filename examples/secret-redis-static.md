# Redis Static Credential Benchmark (`redis_static_secret`) 

This benchmark will test the static generation of redis credentials.

~> We highly recommended that you use a Vault-specific user rather than the admin user
in your database when configuring the plugin. This user will be used to
create/update/delete users within the database so it will need to have the appropriate
permissions to do so.

## Benchmark Configuration Parameters
### DB Configuration (`db`)
- `name` `(string: "benchmark-redis-db")` - Name for this database connection.
- `plugin_name` `(string: "redis-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` `(list: ["my-*-role"])` - List of the roles allowed to use this connection. 
- `host` `(string: <required>)` - Specifies the host to connect to.
- `port` `(int: <required>)` - Specifies the port to connect to. 
- `username` `(string: <required>)` - The root credential username. This can also be provided via the `VAULT_BENCHMARK_STATIC_REDIS_USERNAME` environment variable
- `password` `(string: <required>)` - The root credential password. This can also be provided via the `VAULT_BENCHMARK_STATIC_REDIS_PASSWORD` environment variable
- `tls` `(bool: false)` - Specifies whether to use TLS when connecting to Redis.
- `insecure_tls` `(bool: false)` - Specifies whether to skip verification of the server certificate when using TLS.
- `ca_cert` `(string: optional)` - Specifies whether to use TLS when connecting to Redis.

### Static Role Configuration (`role`)
- `name` `(string: "my-static-role")` - Specifies the name of the role to create. 
- `db_name` `(string: "benchmark-redis-db")` - Specifies the name of the database connection to use for this role.  
- `rotation_period` `(string: "5m")` – Specifies the amount of time Vault should wait before rotating the password. The minimum is 5 seconds.
- `username` `(string: <required>)` – Specifies the database username that this Vault role corresponds to.

## Example HCL 
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

## Example Usage
```bash
$ vault-benchmark run -config=example-configs/config.hcl
2023-04-25T11:19:42.638-0500 [INFO]  vault-benchmark: setting up targets
2023-04-25T11:19:42.658-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-25T11:19:44.663-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op                     count  rate         throughput   mean        95th%       99th%        successRatio
redis_static_secret_1  4818   2408.666450  2404.376084  4.154177ms  4.843807ms  12.356863ms  100.00%
```
