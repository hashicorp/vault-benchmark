# RabbitMQ Secret Configuration Options

This benchmark will test RabbitMQ secret engine operations. In order to use this test, configuration for the RabbitMQ server must be provided as an HCL file with a `rabbitmq_config` body.  Additionally, a `role_config` can also be provided.  The configuration options can be found in the [RabbitMQ Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/rabbitmq#configure-connection).  Example configuration files can be found in the [RabbitMQ configuration directory](/example-configs/rabbitmq/).

## Default RabbitMQ Role Configuration

```json
{
    "name": "benchmark-role",
    "vhosts": "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}"
}
```

## Example Usage

```bash
$ benchmark-vault run -config=example-configs/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op             count  rate        throughput  mean         95th%        99th%        successRatio
rabbit_test_1  796    795.692431  791.605698  12.585419ms  23.516021ms  29.575085ms  100.00%
```
