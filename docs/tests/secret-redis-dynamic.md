# Redis Dynamic Credential Benchmark (`redis_dynamic_secret`)

This benchmark will test the dynamic generation of redis credentials.

~> We highly recommended that you use a Vault-specific user rather than the admin user
in your database when configuring the plugin. This user will be used to
create/update/delete users within the database so it will need to have the appropriate
permissions to do so.

## Benchmark Configuration Parameters

### Database Configuration (`db_connection`)

- `name` `(string: "benchmark-redis-db")` - Name for this database connection.
- `plugin_name` `(string: "redis-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified during initial configuration. Defaults to true.
- `host` `(string: <required>)` - Specifies the host to connect to.
- `port` `(int: <required>)` - Specifies the port to connect to.
- `username` `(string: <required>)` - The root credential username. This can also be provided via the `VAULT_BENCHMARK_REDIS_USERNAME` environment variable.
- `password` `(string: <required>)` - The root credential password. This can also be provided via the `VAULT_BENCHMARK_REDIS_PASSWORD` environment variable.
- `tls` `(bool: false)` - Specifies whether to use TLS when connecting to Redis.
- `insecure_tls` `(bool: false)` - Specifies whether to skip verification of the server certificate when using TLS.
- `ca_cert` `(string: optional)` - Specifies whether to use TLS when connecting to Redis.

### Dynamic Role Configuration (`role`)

- `name` `(string: "my-dynamic-role")` – Specifies the name of the role to create. This is specified as part of the URL.
- `default_ttl` `(string)` - Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (`1h`). Defaults to system/engine default TTL time.
- `max_ttl` `(string)` - Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (`1h`). Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(list: <required>)` – Specifies the database statements executed to create and configure a user. See the plugin's API page
  for more information on support and formatting for this parameter.

## Example HCL

```hcl
test "redis_dynamic_secret" "redis_dynamic_secret_1" {
  weight = 100
  config {
    db_connection {
      host          = "localhost"
      db_name       = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "user"
      password      = "pass"
      tls           = false
    }

    role {
      role_name           = "my-dynamic-role"
      creation_statements = "[\"+@admin\"]"
      default_ttl         = "5m"
      max_ttl             = "1h"
    }
  }
}
```
