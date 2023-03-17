# Elasticsearch Secret Configuration Options

This benchmark will test the dynamic generation of Elasticsearch credentials.


## Test Parameters

### Elasticsearch Config

- `name` _(string: "benchmark-elasticsearch")_: Specifies the name for this database connection.
- `plugin_name` _(string: "elasticsearch-database-plugin")_: Specifies the name of the plugin to use for this connection.
- `url` _(string: <required>)_: Specifies the connection string used to connect to the database.
- `username` _(string: <required>)_: Specifies the name of the user to use as the "root" user when connecting to the database.
- `password` _(string: <required>)_: Specifies the password to use when connecting with the username.
- `allowed_roles` _(string: "benchmark-role")_: List of the roles allowed to use this connection.
- `insecure` _(bool: true)_: Specifies if the connection should use TLS.  Not recommended for production use.

### Role Config

- `name` _(string: "benchmark-role")_: Specifies the name of the role to create.
- `db_name` _(string: "benchmark-elasticsearch")_: The name of the database connection to use for this role.
- `default_ttl` _(string: "1h")_: Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds.
- `max_ttl` _(string: "24h")_:  Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds.
- `creation_statements` _(string: "{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}")_: Specifies the database statements executed to create and configure a user.

## Example Configuration

```hcl
test "elasticsearch_secret" "elasticsearch_test_1" {
    weight = 100
    config {
        db_config {
            url = "https://localhost:9200"
            username = "elastic"
            password = "*M7EJ8VUbEp7lTCmfxoS"
        }
        role_config {
            creation_statements = "{\"elasticsearch_role_definition\": {\"indices\": [{\"names\":[\"*\"], \"privileges\":[\"read\"]}]}}"
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=example-configs/elasticsearch/config.hcl
Setting up targets...
Starting benchmarks. Will run for 2s...
Benchmark complete!
Target: http://127.0.0.1:8200
op                    count  rate       throughput  mean          95th%         99th%         successRatio
elasticsearch_test_1  130    64.854516  60.938865   157.826248ms  225.886833ms  244.436149ms  100.00%
```
