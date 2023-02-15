# Redis Secret Configuration Options

This benchmark will test the dynamic generation of Redis credentials.

In order to use this test, configuration for the Redis instance MUST be provided as a JSON file using the `redis_config_json` flag. The primary required fields are the `host`, `port`, `username` and `password` of the redis instance. If `tls` and `insecure_tls` are not specified, configuration will default to `tls=false` and `insecure_tls=true`. Additional defaults include `allowed_roles=["*"]` and `db_name="redis"`.


 A role configuration file can be passed as well via the `redis_dynamic_role_config_json` or `redis_static_role_config_json` flag.

## Test Parameters (minimum 1 required)
- `pct_redis_dynamic_read`: percent of requests that are Redis dynamic credential generations
- `pct_redis_static_read`: percent of requests that are Redis static credential generations


## Additional Parameters

- `redis_config_json` _(required)_: path to JSON file containing Vault redis configuration.  Configuration options can be found in the [Redis Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/databases/redis).  Example configuration files can be found in the [redis configuration directory](/configs/redis/).
- `redis_dynamic_role_config_json`: path to a JSON file containing the redis dynamic role configuration.
- `redis_static_role_config_json`: path to a JSON file containing the Redis static role configuration.


### Default Redis Role Configuration

 Defaults for dynamic role configuration are:
 ```
 	role_name := "benchmark-role"
	creation_statement := "[\"+@admin\"]"
	ttl := "1h"
	max_ttl := "24h"
```

 Defaults for static role configuration are:
 ```
    "role_name": "benchmark-role",
    "username": "vault-admin",
    "rotation_period": "5m"
```

### Example Usage

```bash
$ vault-benchmark \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_redis_dynamic_read=100 \
    -redis_config_json=./configs/redis/redis_config.json \
    -redis_dynamic_role_config_json=./configs/redis/redis_dynamic_role_config.json
op                            count  rate        throughput  mean         95th%        99th%        successRatio
redis dynamic cred retrieval  7077   707.659551  706.959286  14.137498ms  25.264196ms  67.917547ms  100.00%
```


```bash
$ vault-benchmark \
    -vault_addr=http://localhost:8200 \
    -vault_token=dev \
    -pct_redis_static_read=100 \
    -redis_config_json=/path/to/redis_config.json \
    -redis_static_role_config_json=path/to/redis_static_role_config.json \
    -cleanup=false
op                           count   rate          throughput    mean       95th%       99th%       successRatio
redis static cred retrieval  116183  11618.136135  11616.705220  856.629µs  1.863952ms  2.903061ms  100.00%
```
