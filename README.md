# Vault Benchmark

`vault-benchmark` is a tool designed to test the performance of Vault auth methods and secret engines. Running the binary with a benchmark configuration file, will configure any necessary resources on the Vault instance itself required to perform the tests defined. Any auth methods or secrets engine tests defined that require an external dependency such as a database will require that infrastructure be set up correctly prior to benchmarking. `vault-benchmark` makes use of the [Vegeta](https://github.com/tsenart/vegeta) HTTP load testing utility.

**Warning**
`vault-benchmark` will put a great amount of stress against the cluster itself and the infrastructure that the cluster is running on during testing, and as such is intended to only be run against a test Vault cluster that is isolated from any production systems or any other systems that can cause any negative impact.

# Installation
## Official Release Binaries
You can download a release binary from our [release page](https://releases.hashicorp.com/vault-benchmark)

## Compiling From Source
You can compile the latest version including any fixes or features from source by running `make bin`. This will put the `vault-benchmark` binary in the `dist` folder in directories that map to your `GOOS` and `GOARCH`:
```bash
$ make bin
GOARCH=arm64 GOOS=darwin go build -o dist/darwin/arm64/vault-benchmark
```

# Usage
`vault-benchmark` can be run directly as a binary, docker container or kubernetes job. Below is an example of running the binary.
```
$ vault-benchmark run -config=config.hcl 
2023-04-26T13:02:59.943-0500 [INFO]  vault-benchmark: setting up targets
2023-04-26T13:02:59.993-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-26T13:03:01.994-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op              count  rate         throughput   mean        95th%       99th%       successRatio
approle_test1  8794   4396.873590  4394.241423  2.273698ms  3.164222ms  4.351606ms  100.00%
```

## Docker

**Tip**: Create a Vault Benchmark image with the `make image` command.

First, create a network that Vault and Vault Benchmark will share:

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

Once Vault is running, create a Vault Benchmark container and watch the logs for the results:

```bash
docker run \
  --name=vault-benchmark \
  --hostname=vault-benchmark \
  --network=vault \
  -v ./vault-benchmark/configs/:/opt/vault-benchmark/configs \
  --detach hashicorp/vault-benchmark:0.1.0 \
  vault-benchmark run -config=/opt/vault-benchmark/configs/config.hcl

docker logs -f vault-benchmark
```

# Documentation
Documentation for `vault-benchmark` including usage and test configuration can be found in our [docs](docs/index.md)
