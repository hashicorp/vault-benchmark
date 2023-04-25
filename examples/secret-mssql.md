# MSSQL Secret Benchmark

This benchmark will test the dynamic generation of MSSQL credentials.

## Test Parameters

### DB Config `db`

- `name` `(string: "benchmark-mssql")`: Name for this database connection. This is specified as part of the URL.
- `verify_connection` `(optional)`: Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` `(list: ["benchmark_role"])`: List of the roles allowed to use this connection.
- `root_rotation_statements` `(optional)`: Specifies the database statements to be executed to rotate the root user's credentials.
- `password_policy` `(optional)`: The name of the password policy to use when generating passwords for this database. If not specified, this will use a default policy defined as: 20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `connection_url` `(string: <required>)`: Specifies the MSSQL DSN. This field can be templated and supports passing the username and password parameters in the following format `field_name`. Certificate authentication can be used by setting `?sslinline=true` and giving the SSL credentials in the sslrootcert, sslcert and sslkey credentials. A templated connection URL is required when using root credential rotation. This field supports both format string types, URI and keyword/value. Both formats support multiple host connection strings.
- `max_open_connections` `(int: 4)`: Specifies the maximum number of open connections to the database.
- `max_idle_connections` `(int: 0)`: Specifies the maximum number of idle connections to the database.
- `max_connection_lifetime` `(string: "0s")`: Specifies the maximum amount of time a connection may be reused.
- `username` `(string: "")`: The root credential username used in the connection URL.
- `password` `(string: "")`: The root credential password used in the connection URL.

### Role Config `role`

- `name` `(string: "benchmark-role")`: Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` `(string: "benchmark-mssql")`: The name of the database connection to use for this role.
- `creation_statements` `(string: <required>)`: Specifies the database statements executed to create and configure a user. See the plugin's API page for more information on support and formatting for this parameter.

## Example Configuration

### Only HCL
```hcl
test "mssql_secret" "mssql_test_1" {
    weight = 100
    config {
        db_connection {
            connection_url = "sqlserver://{{username}}:{{password}}@localhost:1433"
            username = "username"
            password = "P@$$word123"
        }

        role {
            creation_statements = "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}'; CREATE USER [{{name}}] FOR LOGIN [{{name}}]; GRANT SELECT ON SCHEMA::dbo TO [{{name}}];"
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
mssql_test_1  249    248.880537  239.605824  41.018154ms  52.821772ms  58.667201ms  100.00%
```

### HCL and JSON

```hcl
test "mssql_secret" "mssql_test_1" {
    weight = 100
    config {
        db_connection {
            connection_url = "sqlserver://{{username}}:{{password}}@localhost:1433"
            username = "username"
            password = "P@SSW0RD"
        }

        role {
            creation_statements = "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}'; CREATE USER [{{name}}] FOR LOGIN [{{name}}]; GRANT SELECT ON SCHEMA::dbo TO [{{name}}];"
        }
    }
}
```

```bash
$ vault-benchmark run -config=example-configs/mssql/config.hcl
2023-04-24T09:42:15.172-0500 [INFO]  vault-benchmark: setting up targets
2023-04-24T09:42:15.323-0500 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2023-04-24T09:42:26.531-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op            count  rate       throughput  mean          95th%         99th%         successRatio
mssql_test_1  103    10.218976  9.191248    1.033933462s  1.227400016s  1.275721642s  100.00%
```
