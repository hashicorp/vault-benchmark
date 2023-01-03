# RabbitMQ Secret Configuration Options

This benchmark will test RabbitMQ secret engine operations. In order to use this test, configuration for the RabbitMQ server must be provided as a JSON file using the `rabbitmq_config_json` flag. The primary required fields are the `username` and `password` for the user configured in RabbitMQ for Vault to use, as well as the `connection_uri` field that defines the address to be used.

## Test Parameters (minimum 1 required)

- `pct_rabbitmq_read`: percent of requests that are RabbitMQ Dynamic Credential generations

## Additional Parameters

- `rabbitmq_config_json` _(required)_: path to JSON file containing Vault RabbitMQ configuration.  The configuration options can be found in the [RabbitMQ Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/rabbitmq#configure-connection).  Example configuration files can be found in the [RabbitMQ configuration directory](/configs/rabbitmq/).
- `rabbitmq_role_config_json`: path to a JSON file containing the RabbitMQ role configuration. If this is not specified, a default configuration will be used (see below).

### Default RabbitMQ Role Configuration

```json
{
    "name": "benchmark-role",
    "vhosts": "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}",
}
```

### Example Usage

```bash
$ benchmark-vault \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_rabbitmq_read=100 \
    -rabbitmq_config_json=/path/to/rabbitmq/config.json \
    -rabbitmq_role_config_json=/path/to/rabbitmq/role/config.json

op                     count  rate        throughput  mean         95th%       99th%        successRatio
rabbit cred retrieval  8154   815.079324  814.489248  12.261012ms  18.03222ms  70.963221ms  100.00%
```
