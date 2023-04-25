# Dynamic Secrets Engine Benchmark
This benchmark will test the dynamic generation of redis credentials. In order to use this test, configuration for the target redis database must be provided as part of the configuration. 

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

### Dynamic Role Config `role`
- `name` `(string: "my-dynamic-role")` – Specifies the name of the role to create. This is specified as part of the URL. 
- `default_ttl` `(string/int: 0)` - Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (`1h`) or an integer
  number of seconds. Defaults to system/engine default TTL time.
- `max_ttl` `(string/int: 0)` - Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (`1h`) or an integer
  number of seconds. Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(list: <required>)` – Specifies the database statements executed to create and configure a user. See the plugin's API page
  for more information on support and formatting for this parameter.


### Example vault-benchmark config map YAML
```hcl
test "redis_dynamic_secret" "redis_dynamic_secret_1" {
  weight = 100
  config {
    db {
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

```bash
$ vault-benchmark run -config=example-configs/config.hcl
2023-04-25T11:27:49.323-0500 [INFO]  vault-benchmark: setting up targets
2023-04-25T11:27:49.345-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-25T11:27:51.349-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op                      count  rate         throughput   mean        95th%       99th%        successRatio
redis_dynamic_secret_1  4922   2460.722400  2456.618212  4.065801ms  5.248935ms  10.719219ms  100.00%
```

