# RabbitMQ Secret Configuration Options

This benchmark will test RabbitMQ secret engine operations. In order to use this test, configuration for the RabbitMQ server must be provided as an HCL file with a `rabbitmq_config` body.  Additionally, a `role_config` can also be provided.  The configuration options can be found in the [RabbitMQ Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/rabbitmq#configure-connection).  Example configuration files can be found in the [RabbitMQ configuration directory](/example-configs/rabbitmq/).

## Default RabbitMQ Role Configuration

```json
{
    "name": "benchmark-role",
    "vhosts": "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}"
}
```
