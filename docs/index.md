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

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
```

## Subcommands

- [Run](commands/run.md)
- [Review](commands/review.md)

## Benchmark Tests

Below is a list of all currently available benchmark tests

### Auth Benchmark Tests

- [Approle Authentication Benchmark (`approle_auth`)](tests/auth-approle.md)
- [AWS Authentication Credential Benchmark (`aws_auth`)](tests/auth-aws.md)
- [Azure Authentication Credential Benchmark (`azure_auth`)](tests/auth-azure.md)
- [Certification Authentication Benchmark (`cert_auth`)](tests/auth-certificate.md)
- [Google Cloud Platform Auth Benchmark (`gcp_auth`)](tests/auth-gcp.md)
- [GitHub Auth Benchmark (`github_auth`)](tests/auth-github.md)
- [JWT Static Credential Benchmark (`jwt_auth`)](tests/auth-jwt.md)
- [Kubernetes Auth Benchmark](tests/auth-k8s.md)
- [LDAP Auth Benchmark (`ldap_auth`)](tests/auth-ldap.md)
- [Okta Auth Benchmark (`okta_auth`)](tests/auth-okta.md)
- [Userpass Auth Benchmark (`userpass_auth`)](tests/auth-userpass.md)

### Secret Benchmark Tests

- [AWS Secrets Engine Benchmark (`aws_secret`)](tests/secret-aws.md)
- [Azure Secrets Engine Benchmark (`azure_secret`)](tests/secret-azure.md)
- [Cassandra Secrets Engine Benchmark (`cassandra_secret`)](tests/secret-cassandra.md)
- [Consul Secret Benchmark (`consul_secret`)](tests/secret-consul.md)
- [Couchbase Secrets Engine Benchmark (`couchbase_secret`)](tests/secret-couchbase.md)
- [Cubbyhole Secrets Engine Benchmark (`cubbyhole_secret`)](tests/secret-cubbyhole.md)
- [Elasticsearch Secrets Engine Benchmark (`elasticsearch_secret`)](tests/secret-elasticsearch.md)
- [GCP Secrets Engine Benchmark (`gcp_secret`)](tests/secret-gcp.md)
- [GCP Secrets Engine Benchmark (`gcp_secret`)](tests/secret-impersonate-gcp.md)
- [KVV1 and KVV2 Secret Benchmark](tests/secret-kv.md)
- [LDAP Dynamic Secret Benchmark `ldap_dynamic_secret`](tests/secret-ldap-dynamic.md)
- [LDAP Static Secret Benchmark `ldap_static_secret`](tests/secret-ldap-static.md)
- [MongoDB Secrets Engine Benchmark](tests/secret-mongo.md)
- [MongoDB Atlas Secrets Engine Benchmark](tests/secret-mongodb-atlas.md)
- [MSSQL Secret Benchmark (`mssql_secret`)](tests/secret-mssql.md)
- [MySQL Secret Benchmark `mysql_secret`](tests/secret-mysql.md)
- [Nomad Secrets Engine Benchmark](tests/secret-nomad.md)
- [PKI Secret Configuration Options](tests/secret-pki-issue.md)
- [PKI Sign Secret Configuration Options](tests/secret-pki-sign.md)
- [Postgresql Secrets Engine Benchmark `postgresql_secret`](tests/secret-postgresql.md)
- [RabbitMQ Secret Configuration Options](tests/secret-rabbit.md)
- [Redis Dynamic Credential Benchmark (`redis_dynamic_secret`)](tests/secret-redis-dynamic.md)
- [Redis Static Credential Benchmark (`redis_static_secret`)](tests/secret-redis-static.md)
- [Signed SSH Secret Issue Configuration Options](tests/secret-ssh-issue.md)
- [SSH Key Signing Configuration Options](tests/secret-ssh-sign.md)
- [Secrets Sync Benchmark](tests/secret-sync.md)
- [Transform Tokenization Configuration Options](tests/secret-transform-tokenization.md)
- [Transit Secret Configuration Options](tests/secret-transit.md)

### System Tests

- [System Status Configuration Options](tests/system-status.md)

## Global Configuration Options

- [Global Configuration Options](global-configs.md)
