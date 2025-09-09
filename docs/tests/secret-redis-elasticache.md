# Redis ElastiCache Secrets Engine Benchmark (`redis_elasticache_secret`)

This benchmark will test the static generation of Redis ElastiCache credentials using AWS ElastiCache for Redis.

> **Note:** Redis ElastiCache secrets engine supports only static roles. Dynamic credential generation is not supported for ElastiCache.

## Test Parameters

### DB Configuration (`db_connection`)

- `name` `(string: "benchmark-redis-elasticache")` - Name for this database connection.
- `plugin_name` `(string: "redis-elasticache-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` `(list: ["my-*-role"])` - List of the roles allowed to use this connection.
- `url` `(string: <required>)` - The primary endpoint URL for your ElastiCache cluster (e.g., `primary-endpoint.my-cluster.xxx.yyy.cache.amazonaws.com:6379`).
- `access_key_id` `(string: <optional>)` - AWS access key ID. This can also be provided via the `VAULT_BENCHMARK_REDIS_ELASTICACHE_ACCESS_KEY_ID` environment variable. If omitted, authentication falls back to the AWS credentials provider chain.
- `secret_access_key` `(string: <optional>)` - AWS secret access key. This can also be provided via the `VAULT_BENCHMARK_REDIS_ELASTICACHE_SECRET_ACCESS_KEY` environment variable. If omitted, authentication falls back to the AWS credentials provider chain.
- `region` `(string: "us-east-1")` - AWS region where your ElastiCache cluster is located. This can also be provided via the `VAULT_BENCHMARK_REDIS_ELASTICACHE_REGION` environment variable.
- `username` `(string: <optional>)` - **Deprecated** but supported for backward compatibility. Use `access_key_id` instead.
- `password` `(string: <optional>)` - **Deprecated** but supported for backward compatibility. Use `secret_access_key` instead.

### Static Role Configuration (`static_role`)

- `name` `(string: "my-static-role")` - Specifies the name of the static role to create.
- `db_name` `(string: "benchmark-redis-elasticache")` - Specifies the name of the database connection to use for this role.
- `username` `(string: <required>)` - Specifies the ElastiCache username that this Vault role corresponds to. This can also be provided via the `VAULT_BENCHMARK_REDIS_ELASTICACHE_USERNAME` environment variable.
- `rotation_period` `(string: "5m")` – Specifies the amount of time Vault should wait before rotating the password. The minimum is 5 seconds.

## Environment Variables

The following environment variables can be used to provide sensitive configuration:

- `VAULT_BENCHMARK_REDIS_ELASTICACHE_ACCESS_KEY_ID` - AWS access key ID
- `VAULT_BENCHMARK_REDIS_ELASTICACHE_SECRET_ACCESS_KEY` - AWS secret access key
- `VAULT_BENCHMARK_REDIS_ELASTICACHE_REGION` - AWS region
- `VAULT_BENCHMARK_REDIS_ELASTICACHE_USERNAME` - ElastiCache username for static role

## Prerequisites

1. **AWS ElastiCache Cluster**: You need a running ElastiCache for Redis cluster with Redis AUTH enabled.
2. **AWS Permissions**: The provided AWS credentials must have sufficient permissions to manage ElastiCache users:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "elasticache:ModifyUser",
           "elasticache:DescribeUsers"
         ],
         "Resource": "arn:aws:elasticache:<region>:<account-id>:user:*"
       }
     ]
   }
   ```
3. **ElastiCache User**: The username specified in the static role must already exist in your ElastiCache cluster.

## Example HCL

```hcl
test "redis_elasticache_secret" "redis_elasticache_test" {
    weight = 100
    config {
        db_connection {
            name = "my-redis-elasticache"
            plugin_name = "redis-elasticache-database-plugin"
            url = "primary-endpoint.my-cluster.xxx.yyy.cache.amazonaws.com:6379"
            access_key_id = "AKIAIOSFODNN7EXAMPLE"
            secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            region = "us-east-1"
            allowed_roles = ["my-*-role"]
        }
        
        static_role {
            name = "my-elasticache-role"
            db_name = "my-redis-elasticache"
            username = "vault-user"
            rotation_period = "10m"
        }
    }
}
```

## Example Usage with Environment Variables

```hcl
test "redis_elasticache_secret" "redis_elasticache_env_test" {
    weight = 100
    config {
        db_connection {
            name = "my-redis-elasticache"
            url = "primary-endpoint.my-cluster.xxx.yyy.cache.amazonaws.com:6379"
            region = "us-west-2"
            allowed_roles = ["vault-*"]
        }
        
        static_role {
            name = "env-elasticache-role"
            db_name = "my-redis-elasticache"
            rotation_period = "30m"
        }
    }
}

test "redis_elasticache_secret" "elasticache_benchmark" {
    weight = 100
    config {
        db_connection {
            name = "vault-cache"
            plugin_name = "redis-elasticache-database-plugin"
            allowed_roles = ["benchmark-role"]
            # AWS credentials for accessing ElastiCache
            url = "primary-endpoint.my-cluster.xxx.yyy.cache.amazonaws.com:6379"
        }

        static_role {
            name = "benchmark-role"
            db_name = "vault-cache"
            username = "vault-cache-user"
	        rotation_period = "5m"
        }
    }
}
```

Set the environment variables:
```bash
export VAULT_BENCHMARK_REDIS_ELASTICACHE_ACCESS_KEY_ID="your-access-key"
export VAULT_BENCHMARK_REDIS_ELASTICACHE_SECRET_ACCESS_KEY="your-secret-key"
export VAULT_BENCHMARK_REDIS_ELASTICACHE_USERNAME="your-elasticache-user"
```

## Example Usage

```bash
$ ./vault-benchmark run -config=config.hcl
2025-09-09T06:49:39.955Z [INFO]  vault-benchmark: setting up targets
2025-09-09T06:49:40.235Z [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-09-09T06:50:10.242Z [INFO]  vault-benchmark: cleaning up targets
2025-09-09T06:50:10.288Z [INFO]  vault-benchmark: benchmark complete
Target: https://127.0.0.1:8200
op                     count  rate         throughput   mean        95th%        99th%        successRatio
elasticache_benchmark  15483  1548.202225  1547.845736  6.340021ms  12.567514ms  19.445834ms  100.00%
```

## Important Notes

- **Static Roles Only**: Redis ElastiCache secrets engine only supports static roles. Dynamic credential generation is not available.
- **Password Propagation Delay**: New passwords may take up to a couple of minutes before ElastiCache completes their configuration. It's recommended to use a retry strategy when establishing new Redis ElastiCache connections.
- **AWS Credentials**: If `access_key_id` and `secret_access_key` are not provided, authentication falls back to the AWS credentials provider chain (IAM roles, environment variables, etc.).
- **Minimum Rotation Period**: The minimum rotation period is 5 seconds, though longer periods are recommended for production use.
