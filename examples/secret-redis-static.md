# Redis Secret Configuration Options

This benchmark will test the tatic generation of redis credentials.

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

### Static Role Config
- `role_name` _(string: "my-static-role")_: Specifies the name of the role to create. 
- `rotation_period` _(string/int)_ – Specifies the amount of time Vault should wait before rotating the password. The minimum is 5 seconds.
- `username` _(string: <required>)_ – Specifies the database username that this Vault role corresponds to.

## Example Configuration 
### Static Roles
```hcl
test "redis_static_secret" "redis_static_secret_1" {
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
redis_static_secret_1   4359   2179.418817  2176.057613  3.535716ms  4.601893ms  6.903003ms  100.00%
```

### HCL and JSON
```hcl
test "redis_static_secret" "redis_static_secret_1" {
  weight = 100
  config {
    db {
      host          = "localhost"
      db_name       = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      tls           = false
    }

    role {
      role_name       = "my-s-role"
      rotation_period = "5m"
      username        = "my-static-role"
    }
  }
}
```

```bash
$ vault-benchmark run -config=example-configs/config.hcl -redis_static_test_user_json=user.json
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate         throughput   mean        95th%       99th%       successRatio
redis_static_secret_1   4359   2179.418817  2176.057613  3.535716ms  4.601893ms  6.903003ms  100.00%
```
