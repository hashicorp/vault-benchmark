# Vault Benchmark
`vault-benchmark` has two subcommands, `run` and `review`. The `run` command is the main command used to execute a benchmark run using the provided benchmark test configuration. Configuration is provided as an HCL formatted file containing the desired global configuration options for `vault-benchmark` itself as well as the test definitions and their respective configuration options.

## Example Config
```hcl
# Global vault-benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
vault_namespace="root"
duration = "2s"
report_mode = "terse"
random_mounts = true
cleanup = true

# Test definitions and configuration
test "approle_auth" "approle_auth_test1" {
    weight = 100
    config {
        role {
            role_name = "benchmark-role"
            token_ttl="2m"
        }
    }
}
```

## Subcommands
- [Run](commands/run.md)
- [Review](commands/review.md)

## Benchmark Tests

### Auth Benchmark Tests
- [Approle](tests/auth-approle.md)
- [AWS](tests/auth-aws.md)
- [Azure](tests/auth-azure.md)
- [GCP](tests/auth-gcp.md)
- [Github](tests/auth-github.md)
- [TLS Certificates](tests/auth-certificate.md) 
- [JWT](tests/auth-jwt.md)
- [Kubernetes](tests/auth-k8s.md)
- [LDAP](tests/auth-ldap.md)
- [Userpass](tests/auth-userpass.md)

### Secrets Benchmark Tests
- [AWS](tests/secret-aws.md)
- [Azure](tests/secret-azure.md)
- [Cassandra](tests/secret-cassandra.md) 
- [Consul](tests/secret-consul.md) 
- [Couchbase](tests/secret-couchbase.md)
- [ElasticSearch](tests/secret-elasticsearch.md)
- [GCP](tests/secret-gcp.md)
- [GCP Impersonation](tests/secret-impersonate-gcp.md)
- [KV](tests/secret-kv.md.md)
- [LDAP (Dynamic)](tests/secret-ldap-dynamic.md)
- [LDAP (Static)](tests/secret-ldap-static.md)
- [MongoDB](tests/secret-mongo.md)
- [MSSQL](tests/secret-mssql.md)
- [MySQL](tests/secret-mysql.md)
- [Nomad](tests/secret-nomad.md)
- [PKI (Issue)](tests/secret-pki-issue.md)
- [PKI (Sign)](tests/secret-pki-sign.md)
- [PostgreSQL](tests/secret-postgresql.md)
- [RabbitMQ](tests/secret-rabbit.md)
- [Redis (Dynamic)](tests/secret-redis-dynamic.md)
- [Redis (Static)](tests/secret-redis-static.md)
- [SSH (Issue)](tests/secret-ssh-issue.md)
- [SSH (Sign)](tests/secret-ssh-sign.md)
- [Transform (Tokenization)](tests/secret-transform-tokenization.md)
- [Transit](tests/secret-transit.md)
- [System Status (sys/status)](tests/system-status.md)

## Global Configuration Options
`-annotate` `(string: "")` - Comma-separated name=value pairs include in `bench_running` prometheus metric. Try name 'testname' for dashboard example.

`-audit_path` `(string: "")` - Path to file for audit log storage.

`-ca_pem_file` `(string: "")` - Path to PEM encoded CA file to verify external Vault. This can also be specified via the `VAULT_CACERT` environment variable.

`-cleanup` `(bool: false)` - Cleanup benchmark artifacts after run.

`-cluster_json` `(string: "")` - Path to cluster.json file

`-debug` `(bool: false)` - Run vault-benchmark in Debug mode. The default is false.

`-duration` `(string: "10s")` - Test Duration.

`-log_level` `(string: "INFO")` - Level to emit logs. Options are: INFO, WARN, DEBUG, TRACE. This can also be specified via the `VAULT_BENCHMARK_LOG_LEVEL` environment variable.

`-pprof_interval` `(string: "")` - Collection interval for vault debug pprof profiling.

`-random_mounts` `(bool: true)` - Use random mount names.

`-report_mode` `(string: "terse")` - Reporting Mode. Options are: terse, verbose, json.

`-rps` `(int: 0)` - Requests per second. Setting to 0 means as fast as possible.

`-vault_addr` `(string:"http://127.0.0.1:8200")` - Target Vault API Address. This can also be specified via the `VAULT_ADDR` environment variable.

`-vault_namespace` `(string:"")` - Vault Namespace to create test mounts. This can also be specified via the `VAULT_NAMESPACE` environment variable.

`-vault_token` `(string: required)` - Vault Token to be used for test setup. This can also be specified via the `VAULT_TOKEN` environment variable.

`-workers` `(int: 10)` - Number of workers The default is 10.
