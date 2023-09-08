# Vault Benchmark

`vault-benchmark` has two subcommands, `run` and `review`. The `run` command is the main command used to execute a benchmark run using the provided benchmark test configuration. Configuration is provided as an HCL formatted file containing the desired global configuration options for `vault-benchmark` itself as well as the test definitions and their respective configuration options.

## Example Config

```hcl

# Global vault-benchmark config options

vault_addr = \"<http://127.0.0.1:8200\>"
vault_token = \"root\"
vault_namespace=\"root\"
duration = \"2s\"
report_mode = \"terse\"
random_mounts = true
cleanup = true

# Test definitions and configuration

test \"approle_auth\" \"approle_auth_test1\" {
    weight = 100
    config {
        role {
            role_name = \"benchmark-role\"
            token_ttl=\"2m\"
        }
    }
}
```

## Subcommands

- [Run](commands/run.md)
- [Review](commands/review.md)

## Benchmark Tests

Below is a list of all currently available benchmark tests

### Auth Benchmark Tests

- [Approle Authentication Benchmark (`approle_auth`)](docs/tests/auth-approle.md)
- [AWS Authentication Credential Benchmark (`aws_auth`)](docs/tests/auth-aws.md)
- [Azure Authentication Credential Benchmark (`azure_auth`)](docs/tests/auth-azure.md)
- [Certification Authentication Benchmark (`cert_auth`)](docs/tests/auth-certificate.md)
- [Google Cloud Platform Auth Benchmark (`gcp_auth`)](docs/tests/auth-gcp.md)
- [GitHub Auth Benchmark (`github_auth`)](docs/tests/auth-github.md)
- [JWT Static Credential Benchmark (`jwt_auth`)](docs/tests/auth-jwt.md)
- [Kubernetes Auth Benchmark](docs/tests/auth-k8s.md)
- [LDAP Auth Benchmark (`ldap_auth`)](docs/tests/auth-ldap.md)
- [Userpass Auth Benchmark (`userpass_auth`)](docs/tests/auth-userpass.md)

### Secret Benchmark Tests

- [AWS Secrets Engine Benchmark (`aws_secret`)](docs/tests/secret-aws.md)
- [Azure Secrets Engine Benchmark (`azure_secret`)](docs/tests/secret-azure.md)
- [Cassandra Secrets Engine Benchmark (`cassandra_secret`)](docs/tests/secret-cassandra.md)
- [Consul Secret Benchmark (`consul_secret`)](docs/tests/secret-consul.md)
- [Couchbase Secrets Engine Benchmark (`couchbase_secret`)](docs/tests/secret-couchbase.md)
- [Elasticsearch Secrets Engine Benchmark (`elasticsearch_secret`)](docs/tests/secret-elasticsearch.md)
- [GCP Secrets Engine Benchmark (`gcp_secret`)](docs/tests/secret-gcp.md)
- [GCP Secrets Engine Benchmark (`gcp_secret`)](docs/tests/secret-impersonate-gcp.md)
- [KVV1 and KVV2 Secret Benchmark](docs/tests/secret-kv.md)
- [LDAP Dynamic Secret Benchmark `ldap_dynamic_secret`](docs/tests/secret-ldap-dynamic.md)
- [LDAP Static Secret Benchmark `ldap_static_secret`](docs/tests/secret-ldap-static.md)
- [MongoDB Secrets Engine Benchmark](docs/tests/secret-mongo.md)
- [MSSQL Secret Benchmark (`mssql_secret`)](docs/tests/secret-mssql.md)
- [MySQL Secret Benchmark `mysql_secret`](docs/tests/secret-mysql.md)
- [Nomad Secrets Engine Benchmark](docs/tests/secret-nomad.md)
- [PKI Secret Configuration Options](docs/tests/secret-pki-issue.md)
- [PKI Sign Secret Configuration Options](docs/tests/secret-pki-sign.md)
- [Postgresql Secrets Engine Benchmark `postgresql_secret`](docs/tests/secret-postgresql.md)
- [RabbitMQ Secret Configuration Options](docs/tests/secret-rabbit.md)
- [Redis Dynamic Credential Benchmark (`redis_dynamic_secret`)](docs/tests/secret-redis-dynamic.md)
- [Redis Static Credential Benchmark (`redis_static_secret`)](docs/tests/secret-redis-static.md)
- [Signed SSH Secret Issue Configuration Options](docs/tests/secret-ssh-issue.md)
- [SSH Key Signing Configuration Options](docs/tests/secret-ssh-sign.md)
- [Transform Tokenization Configuration Options](docs/tests/secret-transform-tokenization.md)
- [Transit Secret Configuration Options](docs/tests/secret-transit.md)

### System Tests

- [System Status Configuration Options](docs/tests/system-status.md)

## Global Configuration Options

- [Global Configuration Options](global-configs.md)
