# benchmark-vault

benchmark-vault is a benchmark tool for Vault.

The main generic options are:
- `workers`: number of workers aka virtual users
- `duration`: benchmark duration
- `rps`: requests per second

benchmark-vault will create `workers` virtual users which will continuously
generate requests to the Vault API.  The requests to generate are controlled
by test options, which must sum to 100.

Tests options:
- `pct_kvv1_write`: percent of requests that are kvv1 writes
- `pct_kvv1_read`: percent of requests that are kvv1 reads
- `pct_kvv2_write`: percent of requests that are kvv2 writes
- `pct_kvv2_read`: percent of requests that are kvv2 reads
- `pct_approle_login`: percent of requests that are approle logins
- `pct_cert_login`: percent of requests that are cert logins
- `pct_pki_issue`: percent of requests that are pki issues
- `pki_gen_lease`: when running PKI issue tests, set to true to generate leases for each cert
- `pct_cassandradb_read`: percent of requests that are CassandraDB Dynamic Credential generations
- `pct_couchbase_read`: percent of requests that are Couchbase dynamic credential generations
- `pct_ldap_login`: percent of requests that are LDAP logins
- `pct_k8s_login`: percent of requests that are Kubernetes logins
- `pct_postgresql_read`: percent of requests that are PostgreSQL credential generations
- `pct_ssh_sign`: percent of requests that are SSH Client Key Sign operations

There is also a `numkvs` option: if any kvv1 or kvv2 requests are specified,
then this many keys will be written during the setup phase.  The read operations
will read from these keys, and the write operations overwrite them.

# Vault cluster

benchmark_vault requires either the `vault_addr` and `vault_token` arguments or
the environment variables `VAULT_ADDR` and `VAULT_TOKEN` to be set.

The Vault cluster doesn't require any mounts: these will be setup at random
mount points as part of the test prep.  This means the vault token must have
sufficient privileges to do that.

# Examples

```
$ vault server -dev-listen-address=0.0.0.0:8200 -dev -dev-root-token-id=devroot >/dev/null 2>&1 &
[1] 67334
$ ./benchmark-vault -vault_addr=http://localhost:8200 -vault_token=devroot -pct_kvv1_read=90 -pct_kvv1_write=10
op          mean       95th%       99th        successRatio
kvv1 read   817.22µs   1.674553ms  2.437689ms  100.00%
kvv1 write  905.852µs  1.825512ms  2.59166ms   100.00%
```

# Tests
## CassandraDB

This benchmark will test the dynamic generation of CassandraDB credentials. In order to use this test, configuration for the CassandraDB instance must be provided as a JSON file using the `cassandradb_config_json` flag. The primary required fields are the `username` and `password` for the user configured in CassandraDB for Vault to use, as well as the `hosts` field that defines the addresses to be use and the `protocol_version`. Below is an example configuration to communicate with a locally running test environment:

```
{
    "hosts": "127.0.0.1",
    "protocol_version": 4,
    "username":"vault",
    "password":"vault"
}
```

Please refer to the [CassandraDB Vault documentation](https://www.vaultproject.io/api-docs/secret/databases/cassandra) for all available configuration options.

A role configuration file can also be passed via the `cassandradb_role_config_json` flag. This allows more specific options to be specified if required by the CassandraDB environment setup. By default the following role `benchmark-role` is defined and used:
```
{
	"default_ttl": "1h",
	"max_ttl": "24h",
	"creation_statements": "CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"
}
```
Any configuration passed will modify the `benchmark-role`.

## PostgreSQL

This benchmark will test the dynamic generation of PostgreSQL credentials. In order to use this test, configuration for the PostgreSQL instance must be provided as a JSON file using the `postgresql_config_json` flag. The primary required fields are the `username` and `password` for the user configured in PostgreSQL for Vault to use, as well as the `connection_url` field that defines the address to be used as well as any other parameters that need to be passed via the URL. Below is an example configuration to communicate with a locally running test environment:

```
{
  "username":"postgres",
  "password":"password",
  "connection_url":"postgresql://{{username}}:{{password}}@localhost:5432/?sslmode=disable"
}
```

Please refer to the [PostgreSQL Vault documentation](https://www.vaultproject.io/docs/secrets/databases/postgresql) for all available configuration options.

A role configuration file can also be passed via the `postgresql_role_config_json` flag. This allows more specific options to be specified if required by the PostgreSQL environment setup. By default the following role `benchmark-role` is defined and used:
```
{
	"default_ttl": "1h",
	"max_ttl": "24h",
	"creation_statements": "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
}
```
Any configuration passed will modify the `benchmark-role`.

## Couchbase

This benchmark will test the dynamic generation of Couchbase credentials. In order to use this test, configuration for the Couchbase instance must be provided as a JSON file using the `couchbase_config_json` flag. The primary required fields are the `username` and `password` for the user configured in Couchbase for Vault to use, as well as the `hosts` field that defines the addresses to use. Below is an example configuration to communicate with a locally running test environment:

```
{
    "hosts": "couchbase://127.0.0.1",
    "username":"vault",
    "password":"vault"
}
```

Please refer to the [Couchbase Vault documentation](https://www.vaultproject.io/api-docs/secret/databases/couchbase) for all available configuration options.

A role configuration file can also be passed via the `couchbase_role_config_json` flag. This allows more specific options to be specified if required by the Couchbase environment setup. By default the following role `benchmark-role` is defined and used:
```
{
	"default_ttl": "1h",
	"max_ttl": "24h",
	"creation_statements": "{\"Roles\": [{\"role\":\"ro_admin\"}]}"
}
```
Any configuration passed will modify the `benchmark-role`.

## LDAP Auth

This benchmark will test LDAP Authentication to Vault. In order to use this test, configuration for the target LDAP server(s) must be provided as a JSON file using the `ldap_config_json` flag. The primary required fields are `url` and `groupdn` depending on the LDAP environment setup and desired connection method. Below is an example configuration to communicate with a locally running LDAP test environment:

```
{
	"url":"ldap://127.0.0.1",
	"userdn":"ou=users,dc=hashicorp,dc=com",
	"groupdn":"ou=groups,dc=hashicorp,dc=com",
	"binddn":"cn=admin,dc=hashicorp,dc=com",
	"bindpass":"admin",
	"userattr":"uid",
	"groupattr":"cn",
	"groupfilter":"(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"
}
```

Please refer to the [Vault LDAP Auth documentation](https://www.vaultproject.io/api-docs/auth/ldap) for all available configuration options.

## Kubernetes Auth

This benchmark will test Vault authentication using the Kubernetes Auth method. In order to use this test, configuration for the target Kubernetes cluster must be provided as a JSON file using the `k8s_config_json` flag. The primary required field is `kubernetes_host`. A role config also needs to be passed with the primary required fields being `name`, `bound_service_account_names`, and `bound_service_account_namespaces`. Included is an example `benchmark-vault-job.yaml` file which can be applied to use the benchmark-vault image in a Kubernetes cluster. This example assumes a Vault cluster deployed in a Kubernetes environment based on our [Vault Installation to Minikube via Helm with Integrated Storage](https://learn.hashicorp.com/tutorials/vault/kubernetes-minikube-raft?in=vault/kubernetes) learn guide. This file can be edited to suit a specific deployment methodology. Below is the ConfigMap snippet showing example configuration:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: benchmark-vault-configmap
data:
  k8s_config.json: |
    {
      "kubernetes_host":"https://kubernetes.default.svc"
    }
  k8s_role_config.json: |
    {
      "name":"benchmark-vault-role",
      "bound_service_account_names":["benchmark-vault"],
      "bound_service_account_namespaces":["*"],
      "token_max_ttl":"24h",
      "token_ttl":"1h"
    }
```

Please refer to the [Vault Kubernetes Auth Method](https://www.vaultproject.io/api-docs/auth/kubernetes) documentation for all available configuration options.

## SSH Key Signing

This benchmark will test throughput for SSH Key Signing. This test defaults to Client Key signing, but you can provide configuration for both the CA and Signer Role by using the `ssh_signer_ca_config_json` and `ssh_signer_role_config_json` flags respectively. Default configurations are as follows:

`/ssh/config/ca`
```
{
  "generate_signing_key": true,
  "key_type": "ssh-rsa",
  "key_bits": 0,
}
```

`/ssh/roles/:name`
```
{
  "name": "benchmark-role",
  "port": 22,
	"key_bits": 1024,
	"algorithm_signer": "default",
	"not_before_duration": "30s",
	"key_type": "ca",
	"allow_user_certificates": true,
}
```

Please refer to the [SSH Secrets Engine](https://developer.hashicorp.com/vault/api-docs/secret/ssh) documenation for all available configuration options.

# Outputs

## Reports

Once the test completes a report is generated on stdout.  The report may
have the following formats:

- `terse`: one line of metrics per test type
- `verbose`: one multi-line block of metrics per test type
- `json`: a blob of JSON containing the full metrics

The main use case for `json` is to preserve the metrics, such that later
benchmark_vault can be invoked with the `input_results` option in order to get
either terse or verbose reports.

## Profiling

`pprof_interval` runs the `vault debug` command to gather pprof data; this
is written to a folder named `vault-debug-X` where X is a timestamp.

# Docker

**Tip**: Create a Benchmark Vault image with the `make image` command.

First, create a network that Vault and Benchmark Vault will share:

```bash
docker network create vault
```

Next, deploy Vault to Docker and ensure it's running:

```bash
docker run \
  --name=vault \
  --hostname=vault \
  --network=vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID="root" \
  -e VAULT_ADDR="http://localhost:8200" \
  -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
  --privileged \
  --detach vault:latest

docker logs -f vault
```

Once Vault is running, create a Benchmark Vault container and watch the logs for the results:

```bash
docker run \
  --name=benchmark-vault \
  --hostname=benchmark-vault \
  --network=vault \
  --detach hashicorp/benchmark-vault:0.0.0-dev \
  benchmark-vault -vault_addr=http://vault:8200 -vault_token=root -pct_kvv1_read=90 -pct_kvv1_write=10

docker logs -f benchmark-vault
```
