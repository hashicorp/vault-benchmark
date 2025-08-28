# Redshift Database Secret Engine

The Redshift database secret engine is one of the supported database secrets engines. This secrets engine allows for the generation of user tokens for AWS Redshift databases.

## Test Parameters

### Redshift DB Connection (`db_connection`) 

| Name | Description | Required | Default | Type |
| ---- | ----------- | -------- | ------- | ---- |
| `name` | Unique name for the database connection | No | `benchmark-redshift` | `string` |
| `plugin_name` | Name of the database plugin to use for this connection | No | `redshift-database-plugin` | `string` |
| `plugin_version` | Version of the database plugin to use | No | (latest) | `string` |
| `verify_connection` | Whether to verify the connection during initial configuration | No | `true` | `boolean` |
| `allowed_roles` | List of roles that are allowed to use this connection | No | `["benchmark-role"]` | `[]string` |
| `root_rotation_statements` | SQL statements to rotate the root password | No | | `[]string` |
| `password_policy` | Name of the password policy to use to generate passwords | No | | `string` |
| `connection_url` | Connection URL for the Redshift cluster | **Yes** | | `string` |
| `max_open_connections` | Maximum number of open connections to the database | No | `4` | `int` |
| `max_idle_connections` | Maximum number of idle connections to the database | No | `0` | `int` |
| `max_connection_lifetime` | Maximum amount of time a connection may be reused | No | `0s` | `string` |
| `username` | Username for the database connection | **Yes** | | `string` |
| `password` | Password for the database connection | **Yes** | | `string` |
| `username_template` | Template for generating usernames | No | | `string` |
| `disable_escaping` | Whether to disable string escaping | No | `false` | `boolean` |

### Redshift Role (`role`)

| Name | Description | Required | Default | Type |
| ---- | ----------- | -------- | ------- | ---- |
| `name` | Unique name for the role | No | `benchmark-role` | `string` |
| `db_name` | Database connection to use for this role | No | `benchmark-redshift` | `string` |
| `default_ttl` | Default TTL for generated credentials | No | | `string` |
| `max_ttl` | Maximum TTL for generated credentials | No | | `string` |
| `creation_statements` | SQL statements to create the database user | **Yes** | | `string` |
| `revocation_statements` | SQL statements to revoke access from the database user | No | | `string` |
| `rollback_statements` | SQL statements to rollback a failed creation | No | | `string` |
| `renew_statements` | SQL statements to renew the database user | No | | `string` |
| `rotation_statements` | SQL statements to rotate the database user's password | No | | `string` |

## Environment Variables

| Name | Description | Required |
| ---- | ----------- | -------- |
| `VAULT_BENCHMARK_REDSHIFT_USERNAME` | Username for Redshift database connection | **Yes** |
| `VAULT_BENCHMARK_REDSHIFT_PASSWORD` | Password for Redshift database connection | **Yes** |

## Connection URL Format

The connection URL should follow this format:
```
postgresql://{{username}}:{{password}}@<redshift-cluster-endpoint>:<port>/<database-name>
```

Example:
```
postgresql://{{username}}:{{password}}@redshift-cluster-1.example.region.redshift.amazonaws.com:5439/dev
```

Note: Even though Redshift uses the PostgreSQL wire protocol, make sure to use the `redshift-database-plugin` plugin name, not `postgresql-database-plugin`.

## Creation Statements

Redshift supports the following template variables in creation statements:
- `{{name}}` - The generated username
- `{{password}}` - The generated password  
- `{{expiration}}` - The expiration timestamp (Redshift-specific)

Example creation statement:
```sql
CREATE USER "{{name}}" PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; 
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
```

## Sample Test Configuration

```hcl
test "redshift_secret" "redshift_benchmark" {
    weight = 100
    config {
        db_connection {
            connection_url = "postgresql://{{username}}:{{password}}@redshift-cluster-1.example.region.redshift.amazonaws.com:5439/dev"
            username = "admin_user"
            password = "admin_password"
            plugin_name = "redshift-database-plugin"
            max_open_connections = 5
            max_idle_connections = 2
        }

        role {
            creation_statements = "CREATE USER \"{{name}}\" PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
            revocation_statements = "DROP USER \"{{name}}\";"
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```


## Example Usage 
```bash
$ ./vault-benchmark run -config=config.hcl
2025-08-26T13:24:32.524+0530 [INFO]  vault-benchmark: setting up targets
2025-08-26T13:24:34.597+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-08-26T13:25:14.460+0530 [INFO]  vault-benchmark: cleaning up targets
2025-08-26T13:25:52.009+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                  count  rate      throughput  mean           95th%        99th%          successRatio
redshift_benchmark  14     1.380391  0.352098    18.490525377s  29.5539708s  29.619659792s  100.00%
```

## Important Notes

1. **Plugin Name**: Always use `redshift-database-plugin`, not `postgresql-database-plugin`
2. **Expiration Template**: Redshift supports the `{{expiration}}` template variable in addition to the standard `{{name}}` and `{{password}}`
3. **Connection Security**: In production, ensure your Redshift cluster is properly secured and accessible only from authorized networks
4. **Credentials**: The provided username/password must have sufficient privileges to create and manage users in the Redshift cluster
5. **Template Reliability**: The implementation avoids template expansion issues by using properly escaped SQL statements to ensure 100% success ratio

## Troubleshooting

Common issues and solutions:

1. **Connection Failures**: Verify that the Redshift cluster endpoint, port, and database name are correct
2. **Authentication Errors**: Ensure the provided credentials have administrative privileges
3. **Network Issues**: Check that the network allows connections to Redshift on port 5439
4. **Plugin Not Found**: Verify that the `redshift-database-plugin` is available in your Vault installation
