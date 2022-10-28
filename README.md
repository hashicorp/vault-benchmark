# benchmark-vault

benchmark-vault is a benchmark tool for Vault.

Vault configuration settings

- `vault_addr`: vault address, overrides VAULT_ADDR
- `cluster_json`: path to cluster.json file
- `vault_token`: vault token, overrides VAULT_TOKEN
- `audit_path`: when creating vault cluster, path to file for audit log
- `ca_pem_file`: when using external vault with HTTPS, path to its CA file in PEM format

The main generic options are:
- `workers`: number of workers aka virtual users
- `duration`: benchmark duration
- `rps`: requests per second
- `report_mode`  reporting mode: terse, verbose, json
- `pprof_interval` collection interval for vault debug pprof profiling
- `input_results` instead of running tests, read a JSON file from a previous test run
- `annotate` comma-separated name=value pairs include in bench_running prometheus metric, try name 'testname' fodashboard example
- `debug` before running tests, execute each benchmark target and output request/response info

benchmark-vault will create `workers` virtual users which will continuously
generate requests to the Vault API.  The requests to generate are controlled
by test options, which must sum to 100.

Additionally, there are test specific options that can be found under that tests designated section.

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
## KVV1 and KVV2

This benchmark tests the performance of KVV1 and/or KVV2.  It writes a set number of keys
(KV1 or KV2) to each mount, then reads them back.  The number of keys is defaulted to 1000, but can
be changed with the `-numkvs` option.  The size of the values is defaulted to 1 character, but can
be changed with the `-kvsize` option.

Configuration Options
- `pct_kvv1_write`: percent of requests that are kvv1 writes
- `pct_kvv1_read`: percent of requests that are kvv1 reads
- `pct_kvv2_write`: percent of requests that are kvv2 writes
- `pct_kvv2_read`: percent of requests that are kvv2 reads
- `numkvs` option: if any kvv1 or kvv2 requests are specified,
then this many keys will be written during the setup phase.  The read operations
will read from these keys, and the write operations overwrite them.

```
$ ./benchmark-vault -pct_kvv1_read=75 -pct_kvv1_write=25 -numkvs=100 -kvsize=10
op          count  rate         throughput   mean       95th%       99th%       successRatio
op          count   rate          throughput    mean       95th%      99th%       successRatio
kvv1 read   207078  20707.991723  20707.303112  342.588µs  792.455µs  1.79457ms   100.00%
kvv1 write  69309   6931.423438   6931.229002   382.028µs  861.062µs  2.103818ms  100.00%

$ ./benchmark-vault -pct_kvv2_read=50 -pct_kvv2_write=50
op          count  rate         throughput   mean       95th%       99th%       successRatio
kvv2 read   99087  9909.216270  9908.109187  396.701µs  927.28µs    1.954493ms  100.00%
kvv2 write  98077  9807.787657  9807.321928  604.503µs  1.348884ms  2.790181ms  100.00%
```

## AppRole

This benchmark tests the performance of logins using the AppRole auth method.

Configuration Options
- `pct_approle_login`: percent of requests that are approle logins

```
$ ./benchmark-vault -pct_approle_login=100
op             count   rate          throughput    mean       95th%       99th%       successRatio
approle login  152174  15217.447491  15216.776175  648.864µs  1.372863ms  2.330503ms  100.00%
```

## Certificate Auth

This benchmark tests the performance of logins using the Certificate auth method.

Configuration Options
- `pct_cert_login`: percent of requests that are cert logins

```
$ ./benchmark-vault -pct_cert_login=100
op          count   rate          throughput  mean       95th%      99th%       successRatio
cert login  319098  31909.905836  0.000000    303.255µs  695.622µs  1.497842ms  0.00%
```

## PKI

This benchmark tests the performance of PKI issue operations.

Configuration Options
- `pct_pki_issue`: percent of requests that are pki issues
- `-pki_setup_delay`: option to allow the PKI backend to be setup before the test starts.  An additional
configuration option,
- `-pki_config_json`: can be used to specify a JSON file containing the PKI configuration
to use.  If this is not specified, a default configuration will be used.

```
$ ./benchmark-vault -pct_pki_issue=100
op         count  rate       throughput  mean          95th%         99th%         successRatio
pki issue  770    76.912068  75.437967   130.886886ms  281.848785ms  424.038003ms  100.00%
```

## Signed SSH Certificates

This benchmark tests the performance of Signed SSH Certificate issue operations.

Configuration Options
- `pct_ssh_ca_issue`: percent of requests that are ssh issue certs
- `-ssh_ca_setup_delay` option to allow the SSH backend to be setup before the test starts.
`-ssh_ca_config_json`: can be used to specify a JSON file containing the SSH CA configuration to use.  If this is
not specified, a default configuration will be used.

```
$ ./benchmark-vault -pct_ssh_ca_issue=100
op         count   rate          throughput  mean       95th%      99th%       successRatio
ssh issue  300282  30028.310228  0.000000    324.823µs  752.144µs  1.601211ms  0.00%
```

## High Availability (HA)

This benchmark tests the performance of HA status requests.

Configuration Options
- `pct_ha_status`: percent of requests that are ha status requests (/sys/ha-status)


```
$ ./benchmark-vault -pct_ha_status=100
op         count   rate          throughput    mean       95th%      99th%       successRatio
ha status  307299  30731.021169  30728.013045  316.743µs  717.639µs  1.705715ms  100.00%
```

## Seal Status

This benchmark tests the performance of the seal status operation, `/sys/seal-status`.

Configuration Options
- `pct_seal_status`: percent of requests that are seal status requests (/sys/seal-status)

```
$ ./benchmark-vault -pct_seal_status=100
op           count   rate          throughput    mean       95th%      99th%       successRatio
seal status  510343  51034.352310  51033.783069  173.612µs  434.735µs  1.116063ms  100.00%
```

## Metrics

This benchmark tests the performance of the metrics operation, `/sys/metrics`.

Configuration Options
- `pct_metrics`: percent of requests that are read requests to metrics (/sys/metrics)

```
$ ./benchmark-vault -pct_metrics=100
op       count   rate          throughput    mean       95th%      99th%       successRatio
metrics  305119  30512.043407  30509.221162  311.575µs  853.498µs  2.214729ms  100.00%
```

## Transit

This benchmark tests the performance of the transit operations.

Configuration Options
- `pct_transit_sign`: percent of requests that are sign requests to transit
- `pct_transit_verify`: percent of requests that are verify requests to transit
- `pct_transit_encrypt`: percent of requests that are encrypt requests to transit
- `pct_transit_decrypt`: percent of requests that are decrypt requests to transit
`-transit_*_setup_delay` options to allow the transit backend to be setup before the test starts.

```
$ ./benchmark-vault -pct_transit_sign=50 -pct_transit_verify=50
op               count  rate         throughput   mean        95th%       99th%       successRatio
transit sign     54570  5457.386815  5456.674805  1.505858ms  2.679909ms  3.661053ms  100.00%
transit verify   26984  2698.373376  2698.320209  344.872µs   802.958µs   1.395324ms  100.00%
```

## CassandraDB

This benchmark will test the dynamic generation of CassandraDB credentials. In order to use this test, configuration for the CassandraDB instance MUST be provided as a JSON file using the `cassandradb_config_json` flag. The primary required fields are the `username` and `password` for the user configured in CassandraDB for Vault to use, as well as the `hosts` field that defines the addresses to be use and the `protocol_version`. Below is an example configuration to communicate with a locally running test environment:

Configuration Options
- `pct_cassandradb_read`: percent of requests that are CassandraDB Dynamic Credential generations

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

Configuration Options
- `pct_postgresql_read`: percent of requests that are PostgreSQL credential generations

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

Configuration Options
- `pct_couchbase_read`: percent of requests that are Couchbase dynamic credential generations

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

Configuration Options
- `pct_ldap_login`: percent of requests that are LDAP logins

Please refer to the [Vault LDAP Auth documentation](https://www.vaultproject.io/api-docs/auth/ldap) for all available configuration options.

## Kubernetes Auth

This benchmark will test Vault authentication using the Kubernetes Auth method. In order to use this test, configuration for the target Kubernetes cluster must be provided as a JSON file using the `k8s_config_json` flag. The primary required field is `kubernetes_host`. A role config also needs to be passed with the primary required fields being `name`, `bound_service_account_names`, and `bound_service_account_namespaces`. Included is an example `benchmark-vault-job.yaml` file which can be applied to use the benchmark-vault image in a Kubernetes cluster. This example assumes a Vault cluster deployed in a Kubernetes environment based on our [Vault Installation to Minikube via Helm with Integrated Storage](https://learn.hashicorp.com/tutorials/vault/kubernetes-minikube-raft?in=vault/kubernetes) learn guide. This file can be edited to suit a specific deployment methodology. Below is the ConfigMap snippet showing example configuration:

Configuration Options
- `pct_k8s_login`: percent of requests that are Kubernetes logins


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

Configuration Options
- `pct_ssh_sign`: percent of requests that are SSH Client Key Sign operations

Please refer to the [SSH Secrets Engine](https://developer.hashicorp.com/vault/api-docs/secret/ssh) documenation for all available configuration options.

```
$ ./benchmark-vault -pct_ssh_sign=100
op                count  rate         throughput   mean        95th%        99th%        successRatio
ssh pub key sign  12946  1294.587852  1293.681384  7.720743ms  10.379888ms  13.079202ms  100.00%
```

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
