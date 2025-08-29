# Oracle Database Secrets Engine Benchmark (`oracle_secret`)

This benchmark will test the dynamic generation of Oracle database credentials.

## Test Parameters

### Database Connection Configuration `db_connection`

- `name` `(string: "benchmark-oracle")` – Specifies the name for this database connection. This is specified as part of the URL.
- `plugin_name` `(string: "oracle-database-plugin")` – Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` – Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified during initial configuration.
- `allowed_roles` `(list: ["benchmark-role"])` – List of the roles allowed to use this connection.
- `root_rotation_statements` `(list: [])` – Specifies the database statements to be executed to rotate the root user's credentials.
- `password_policy` `(string: "")` – The name of the password policy to use when generating passwords for this database.
- `connection_url` `(string: <required>)` – Specifies the Oracle connection URL. See Oracle connection syntax below.
- `username` `(string: "")` – The root credential username used in the connection URL. This can also be provided via the `VAULT_BENCHMARK_ORACLE_USERNAME` environment variable.
- `password` `(string: "")` – The root credential password used in the connection URL. This can also be provided via the `VAULT_BENCHMARK_ORACLE_PASSWORD` environment variable.
- `disable_escaping` `(bool: false)` – Turns off the escaping of special characters inside of the username and password fields.
- `max_open_connections` `(int: 4)` – Specifies the maximum number of open connections to the database.
- `max_idle_connections` `(int: 0)` – Specifies the maximum number of idle connections to the database. A zero uses the value of `max_open_connections` and a negative value disables idle connections.
- `max_connection_lifetime` `(string: "0s")` – Specifies the maximum amount of time a connection may be reused.
- `username_template` `(string: "")` – Template describing how dynamic usernames are generated.
- `split_statements` `(bool: true)` – Whether to split statements on `;` before executing.
- `disconnect_sessions` `(bool: false)` – Whether to disconnect sessions for a user when they are dropped.

### Role Configuration `role`

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create.
- `db_name` `(string: "benchmark-oracle")` – The name of the database connection to use for this role.
- `default_ttl` `(string: "")` – Specifies the TTL for the leases associated with this role. Accepts time suffixed strings ("1h") or an integer number of seconds. Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` – Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings ("1h") or an integer number of seconds. Defaults to system/mount default TTL time.
- `creation_statements` `(string: <required>)` – Specifies the database statements executed to create and configure a user.
- `revocation_statements` `(string: "")` – Specifies the database statements to be executed to revoke a user.
- `rollback_statements` `(string: "")` – Specifies the database statements to be executed to rollback a create operation in the event of an error.
- `renew_statements` `(string: "")` – Specifies the database statements to be executed to renew a user.
- `rotation_statements` `(string: "")` – Specifies the database statements to be executed to rotate the password for a given username.

## Example Configurations

### Basic Oracle Configuration

```hcl
test "oracle_secret" "oracle_test1" {
    weight = 100
    config {
        db_connection {
            connection_url = "{{username}}/{{password}}@localhost:1521/ORCLPDB1"
            username = "system"
            password = "oracle"
        }
        role {
            creation_statements = "CREATE USER {{name}} IDENTIFIED BY \"{{password}}\"; GRANT CONNECT TO {{name}}; GRANT CREATE SESSION TO {{name}};"
            revocation_statements = "DROP USER {{name}} CASCADE;"
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```



### Oracle with Environment Variables

```hcl
test "oracle_secret" "oracle_env_test" {
    weight = 100
    config {
        db_connection {
            connection_url = "{{username}}/{{password}}@localhost:1521/ORCLPDB1"
            # username and password will be read from environment variables:
            # VAULT_BENCHMARK_ORACLE_USERNAME
            # VAULT_BENCHMARK_ORACLE_PASSWORD
        }
        role {
            creation_statements = "CREATE USER {{name}} IDENTIFIED BY \"{{password}}\"; GRANT CONNECT TO {{name}}; GRANT CREATE SESSION TO {{name}};"
            revocation_statements = "DROP USER {{name}} CASCADE;"
            default_ttl = "30m"
            max_ttl = "8h"
        }
    }
}
```



## Prerequisites

To use this benchmark test, you need:

1. **Oracle Database**: A running Oracle database instance 
2. **Network Access**: The Vault server must be able to connect to the Oracle database
3. **Admin Credentials**: Oracle database credentials with privileges to create and drop users
4. **Oracle Plugin**: The Oracle database plugin must be available in your Vault installation

### Oracle Connection URL Format

The connection URL follows this format:
```
oracle://username:password@host:port/service_name
```

Examples:
- `oracle://system:oracle@localhost:1521/xe` (Oracle Express Edition)
- `oracle://admin:password@oracledb.example.com:1521/ORCL` (Standard Oracle)
- `oracle://user:pass@oracle.internal:1521/prod.example.com` (with service name)

### Required Privileges

The database user specified in the connection configuration must have the required privileges. 

## Environment Variables

- `VAULT_BENCHMARK_ORACLE_USERNAME` - Oracle database admin username
- `VAULT_BENCHMARK_ORACLE_PASSWORD` - Oracle database admin password


For more information about the Oracle database secrets engine, see the [Oracle Database secrets engine documentation](https://developer.hashicorp.com/vault/docs/secrets/databases/oracle).


Details about the configuration options can be found in the [Oracle Database secrets engine (API) documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases/oracle).




 ## Example Usage 
```bash
$ vault-benchmark run -config=config.hcl
2025-08-29T14:38:56.533+0530 [INFO]  vault-benchmark: setting up targets
2025-08-29T14:38:56.568+0530 [INFO]  vault-benchmark: starting benchmarks: duration=30s
2025-08-29T14:39:26.636+0530 [INFO]  vault-benchmark: cleaning up targets
2025-08-29T14:40:13.001+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op           count  rate        throughput  mean         95th%       99th%         successRatio
oracle_test  4020   133.998565  133.703155  74.718547ms  94.14937ms  129.425943ms  100.00%
```