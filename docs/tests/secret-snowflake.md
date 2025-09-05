# Snowflake Secrets Engine

This document provides configuration examples and guidance for benchmarking the Snowflake secrets engine in Vault. The Snowflake secrets engine supports both dynamic and static secrets with multiple authentication methods.

## Overview

The Snowflake secrets engine provides:
- **Dynamic Secrets**: Creates temporary users with specified privileges that are automatically cleaned up
- **Static Secrets**: Manages credentials for existing users through periodic rotation

## Authentication Methods

The engine supports two authentication methods:
1. **RSA Key Pair Authentication**: Uses public/private key pairs for authentication
2. **Password Authentication**: Uses username/password for authentication

## Global Configuration Parameters

```hcl
vault_addr      = "http://127.0.0.1:8200"
vault_token     = "root"
duration        = "10s"
cleanup         = true
random_mounts   = true
timeout         = "10s"
```

## Dynamic Secrets Configuration

Dynamic secrets create temporary users in Snowflake with specified privileges and automatically clean them up when the lease expires.

### Dynamic Secrets with RSA Key Pair Authentication

```hcl
test "snowflake_dynamic_secret" "snowflake_dynamic_keypair_test" {
    weight = 100
    config {
        db_connection {
            name = "snowflake-dynamic-keypair-db"
            connection_url = "ACCOUNT_IDENTIFIER.snowflakecomputing.com/DATABASE_NAME"
            account = "ACCOUNT_IDENTIFIER"
            username = "USER_NAME"
            private_key = <<EOF-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----EOF
            warehouse = "WareHouseName"
            database = "DATABASE_NAME"
            schema = "SCHEMA_NAME"
            verify_connection = false
            allowed_roles = ["dynamic-keypair-role"]
        }

        role {
            name = "dynamic-keypair-role"
            db_name = "snowflake-dynamic-keypair-db"
            creation_statements = "CREATE USER {{name}} RSA_PUBLIC_KEY='{{public_key}}' DAYS_TO_EXPIRY = {{expiration}} DEFAULT_ROLE=PUBLIC; GRANT ROLE PUBLIC TO USER {{name}};"
            revocation_statements = "DROP USER {{name}};"
            credential_type = "rsa_private_key"
            credential_config = "key_bits=2048"
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```

### Dynamic Secrets with Password Authentication

```hcl
test "snowflake_dynamic_secret" "snowflake_dynamic_password_test" {
    weight = 100
    config {
        db_connection {
            name = "snowflake-dynamic-password-db"
            connection_url = "USER_NAME:Password@123@ACCOUNT_IDENTIFIER.snowflakecomputing.com"
            account = "ACCOUNT_IDENTIFIER"
            username = "USER_NAME"
            password = "Password@123"
            warehouse = "WAREHOUSE_NAME"
            database = "DATABASE_NAME"
            schema = "SCHEMA_NAME"
            verify_connection = false
            allowed_roles = ["dynamic-password-role"]
        }

        role {
            name = "dynamic-password-role"
            db_name = "snowflake-dynamic-password-db"
            creation_statements = "CREATE USER {{name}} PASSWORD = '{{password}}' DAYS_TO_EXPIRY = {{expiration}} DEFAULT_ROLE=mypasswordrole; GRANT ROLE mypasswordrole TO USER {{name}};"
            revocation_statements = "DROP USER {{name}};"
            credential_type = "password"
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```

## Static Secrets Configuration

Static secrets manage credentials for existing users in Snowflake through periodic rotation.

### Static Secrets with RSA Key Pair Authentication

```hcl
test "snowflake_static_secret" "snowflake_static_keypair_test" {
    weight = 100
    config {
        db_connection {
            name = "my-snowflake-database"
            connection_url = "ACCOUNT_IDENTIFIER.snowflakecomputing.com/DATABASE_NAME"
            account = "ACCOUNT_IDENTIFIER"
            username = "USER_NAME"
            private_key = <<EOF-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----EOF
            allowed_roles = ["my-static-keypair-role"]
        }

        static_role {
            name = "my-static-keypair-role"
            db_name = "my-snowflake-database"
            username = "USER_NAME"
            rotation_statements = "ALTER USER {{name}} SET RSA_PUBLIC_KEY='{{public_key}}'"
            rotation_period = "24h"
            credential_type = "rsa_private_key"
            credential_config = "key_bits=2048"
        }
    }
}
```

### Static Secrets with Password Authentication

```hcl
test "snowflake_static_secret" "snowflake_static_password_test" {
    weight = 100
    config {
        db_connection {
            name = "my-snowflake-database"
            connection_url = "USER_NAME:Password@123@ACCOUNT_IDENTIFIER.snowflakecomputing.com"
            username = "USER_NAME"
            password = "Password@123"
            warehouse = "WAREHOUSE_NAME"
            database = "DATABASE_NAME"
            schema = "SCHEMA_NAME"
            verify_connection = false
            allowed_roles = ["my-static-password-role"]
        }

        static_role {
            name = "my-static-password-role"
            db_name = "my-snowflake-database"
            username = "USER_NAME"
            rotation_statements = "ALTER USER {{name}} SET PASSWORD = '{{password}}'"
            rotation_period = "24h"
        }
    }
}
```

## Connection URL Formats

### RSA Key Pair Authentication
```
connection_url = "ACCOUNT_IDENTIFIER.snowflakecomputing.com/DATABASE_NAME"
```

### Password Authentication
```
connection_url = "USERNAME:PASSWORD@ACCOUNT_IDENTIFIER.snowflakecomputing.com"
```

## Environment Variables

You can use environment variables to avoid hardcoding sensitive information:

```bash
export VAULT_BENCHMARK_SNOWFLAKE_USERNAME="your_username"
export VAULT_BENCHMARK_SNOWFLAKE_PASSWORD="your_password"
export VAULT_BENCHMARK_SNOWFLAKE_ACCOUNT="your_account_identifier"
```

## Database Connection Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `name` | Name of the database connection | Yes |
| `connection_url` | Snowflake connection URL | Yes |
| `account` | Snowflake account identifier | Yes (for key auth) |
| `username` | Database username | Yes |
| `password` | Database password | Yes (for password auth) |
| `private_key` | RSA private key | Yes (for key auth) |
| `warehouse` | Snowflake warehouse | Optional |
| `database` | Snowflake database | Optional |
| `schema` | Snowflake schema | Optional |
| `verify_connection` | Verify database connection | Optional |
| `allowed_roles` | List of allowed role names | Yes |

## Dynamic Role Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `name` | Name of the role | Yes |
| `db_name` | Name of database connection | Yes |
| `creation_statements` | SQL for creating users | Yes |
| `revocation_statements` | SQL for revoking users | Optional |
| `credential_type` | Type of credential (password/rsa_private_key) | Optional |
| `credential_config` | Additional credential configuration | Optional |
| `default_ttl` | Default TTL for credentials | Optional |
| `max_ttl` | Maximum TTL for credentials | Optional |

## Static Role Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `name` | Name of the static role | Yes |
| `db_name` | Name of database connection | Yes |
| `username` | Username for the static role | Yes |
| `rotation_statements` | SQL for rotating credentials | Optional |
| `rotation_period` | How often to rotate credentials | Optional |
| `credential_type` | Type of credential (password/rsa_private_key) | Optional |
| `credential_config` | Additional credential configuration | Optional |

## Test Types

- `snowflake_dynamic_secret`: Tests dynamic secret generation
- `snowflake_static_secret`: Tests static secret rotation

## Usage Examples

Run all tests:
```bash
$ vault-benchmark run -config=snowflake-dynamic-config.hcl
vault-benchmark: setting up targets
2025-09-05T11:14:43.201+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-09-05T11:14:54.261+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                               count  rate      throughput  mean          95th%         99th%         successRatio
snowflake_dynamic_keypair_test   57     5.603429  5.234198    806.967708ms  1.339718976s  1.591427519s  100.00%
snowflake_dynamic_password_test  46     4.791004  4.159118    1.294492084s  2.356407733s  2.805165542s  100.00%

$ vault-benchmark run -config=snowflake-static-config.hcl
2025-09-04T22:48:46.592+0530 [INFO]  vault-benchmark: setting up targets
2025-09-04T22:48:50.327+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-09-04T22:49:00.327+0530 [INFO]  vault-benchmark: cleaning up targets
2025-09-04T22:49:00.328+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                             count   rate          throughput    mean       95th%      99th%      successRatio
snowflake_static_keypair_test  164036  16403.837992  16403.491191  312.844µs  527.953µs  724.231µs  100.00%
snowflake_static_password_test 162956  16295.655066  16295.365823  282.048µs  475.663µs  660.877µs  100.00%
```
The configuration options can be found in the [Snowflake secrets engine (API) documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases/snowflake). 

## Notes

1. **Dynamic secrets** create temporary users that are automatically cleaned up
2. **Static secrets** rotate credentials for existing users
3. **RSA authentication** requires proper key pair setup in Snowflake
4. **Password authentication** uses traditional username/password
5. Ensure the Vault service account has sufficient privileges to create/modify users
6. The `verify_connection` parameter should be set to `false` to avoid connection validation during setup
