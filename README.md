# benchmark-vault

`benchmark-vault` is a tool designed to test the performance of Vault auth methods and secret engines.

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

# Test Cases

## Auth Methods

- [Approle Configurations](/examples/auth-approle.md)
- [Certificate Configurations](/examples/auth-certificate.md)
- [LDAP Configurations](/examples/auth-ldap.md)

## Secret Engines

- [CassandraDB Configurations](/examples/secret-cassandra.md)
- [Couchbase Configurations](/examples/secret-couchbase.md)
- [KV Configurations](/examples/secret-kv.md)
- [LDAP Configurations](/examples/secret-ldap.md)
- [MongoDB Configurations](/examples/secret-mongo.md)
- [PKI Configurations](/examples/secret-pki.md)
- [PostgreSQL Configurations](/examples/secret-postgresql.md)
- [RabbitMQ Configurations](/examples/secret-rabbit.md)
- [SSH Key Signing](/examples/secret-ssh-sign.md)
- [Signed SSH Certificates Configurations](/examples/secret-ssh-sign-ca.md)
- [Transit Configurations](/examples/secret-transit.md)

## System Status

- [System Status Configurations](/examples/system-status.md)

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
