# Redis Secret Configuration Options

This benchmark will test the dynamic generation of redis credentials.

## Test Parameters
### DB Config
- `db_name` _(string: "benchmark-postgres")_: Name for this database connection. 
- `allowed_roles` _(list: ["my-*-role"])_: List of the roles allowed to use this connection. 
- `host` _(string: <required>)_: Specifies the host to connect to.
- `port` _(int: <required>)_: Specifies the port to connect to. 
- `username` _(string: "")_: The root credential username.
- `password` _(string: "")_: The root credential password.
- `tls` _(bool: false)_: Specifies whether to use TLS when connecting to Redis.
- `insecure_tls` _(bool: false)_: Specifies whether to skip verification of the server certificate when using TLS.
- `ca_cert` _(string: optional)_: Specifies whether to use TLS when connecting to Redis.

### Dynamic Role Config
- `role_name` _(string: "my-dynamic-role")_: Specifies the name of the role to create. 
- `default_ttl` _(string: "0")_: Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds. Defaults to system/engine default TTL time.
- `max_ttl` _(string: "0")_:  Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds. Defaults to sys/mounts's default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer.
- `creation_statements` _(list)_: Specifies the database statements executed to create and configure a user. See the plugin's API page for more information on support and formatting for this parameter.

## Example Configuration 
### Dynamic Roles
```hcl
test "redis_secret" "redis_secret_1" {
  weight = 100
  config {
    db_config {
      host          = "localhost"
      db_name       = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "user"
      password      = "pass"
      tls           = false
    }

    dynamic_role_config {
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
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate         throughput   mean        95th%       99th%       successRatio
redis_secret_1  14715  7357.516554  7353.852030  1.356368ms  1.840712ms  2.205115ms  100.00%
```

### HCL and JSON
```hcl
test "redis_secret" "redis_secret_2" {
  weight = 100
  config {
    db_config {
      host          = "localhost"
      db_name       = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "user"
      password      = "pass"
      tls           = false
    }

    static_role_config {
      role_name       = "my-s-role"
      rotation_period = "5m"
      username        = "my-static-role"
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
op              count  rate         throughput   mean        95th%       99th%       successRatio
redis_secret_2  5262   2631.008386  2626.538988  3.803433ms  4.842362ms  6.183915ms  100.00%
```
