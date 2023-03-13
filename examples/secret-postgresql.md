# PostgreSQL Secret Configuration Options

This benchmark will test the dynamic generation of PostgreSQL credentials.

## Test Parameters
### DB Config
- `name` _(string: "benchmark-postgres")_: Name for this database connection. This is specified as part of the URL.
- `allowed_roles` _(list: ["benchmark_role"])_: List of the roles allowed to use this connection. 
- `connection_url` _(string: <required>)_: Specifies the PostgreSQL DSN. This field can be templated and supports passing the username and password parameters in the following format {{field_name}}. Certificate authentication can be used by setting ?sslinline=true and giving the SSL credentials in the sslrootcert, sslcert and sslkey credentials. A templated connection URL is required when using root credential rotation. This field supports both format string types, URI and keyword/value. Both formats support multiple host connection strings. 

### Role Config
- `name` _(string: "benchmark-role")_: Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` _(string: "benchmark-postgres")_: The name of the database connection to use for this role.

## Example Configuration
```hcl
test "postgresql_secret" "postgres_test_1" {
    weight = 100
    config {
        postgresql_db_config {
            connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
            username = "username"
            password = "password"
        }

        postgresql_role_config {
            creation_statements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        }
    }
}


### Example Usage

```bash
$ benchmark-vault run -config=example-configs/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate        throughput  mean         95th%        99th%        successRatio
approle_test_1  249    248.880537  239.605824  41.018154ms  52.821772ms  58.667201ms  100.00%
```
