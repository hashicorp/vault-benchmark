# PostgreSQL Secret Configuration Options

This benchmark will test the dynamic generation of PostgreSQL credentials.

## Test Parameters
### DB Config
- `name` _(string: "benchmark-postgres")_: Name for this database connection. This is specified as part of the URL.
- `verify_connection` _(optional)_: Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` _(list: ["benchmark_role"])_: List of the roles allowed to use this connection. 
- `root_rotation_statements` _(optional)_: Specifies the database statements to be executed to rotate the root user's credentials.
- `password_policy` _(optional)_: The name of the password policy to use when generating passwords for this database. If not specified, this will use a default policy defined as: 20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `connection_url` _(string: <required>)_: Specifies the PostgreSQL DSN. This field can be templated and supports passing the username and password parameters in the following format {{field_name}}. Certificate authentication can be used by setting ?sslinline=true and giving the SSL credentials in the sslrootcert, sslcert and sslkey credentials. A templated connection URL is required when using root credential rotation. This field supports both format string types, URI and keyword/value. Both formats support multiple host connection strings. 
- `max_open_connections` _(int: 4)_: Specifies the maximum number of open connections to the database.
- `max_idle_connections` _(int: 0)_: Specifies the maximum number of idle connections to the database. 
- `max_connection_lifetime` _(string: "0s")_: Specifies the maximum amount of time a connection may be reused.
- `username` _(string: "")_: The root credential username used in the connection URL.
- `password` _(string: "")_: The root credential password used in the connection URL.


### Role Config
- `name` _(string: "benchmark-role")_: Specifies the name of the role to create. This is specified as part of the URL.
- db_name` _(string: "benchmark-postgres")_: The name of the database connection to use for this role.

## Example Configuration 
### Only HCL
```hcl
test "postgresql_secret" "postgres_test_1" {
    weight = 100
    config {
        db_config {
            connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
            username = "username"
            password = "password"
        }

        role_config {
            creation_statements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
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
postgres_test_1  249    248.880537  239.605824  41.018154ms  52.821772ms  58.667201ms  100.00%
```

### HCL and JSON
```hcl
test "postgresql_secret" "postgres_test_1" {
    weight = 100
    config {
        db_config {
            connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
        }

        role_config {
            creation_statements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        }
    }
}
```

```json
{
    "username": "username",
    "password": "password"
}
```

```bash
$ vault-benchmark run -config=example-configs/config.hcl -postgres_test_user_json=user.json
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate        throughput  mean         95th%        99th%        successRatio
postgres_test_1  260    259.460333  245.044207  40.086479ms  59.975645ms  68.40487ms  100.00%
```