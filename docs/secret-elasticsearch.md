# Elasticsearch Secret Configuration Options

This benchmark will test the dynamic generation of Elasticsearch credentials.

## Test Parameters

### Elasticsearch Database Config `db_connection`

- `name` `(string: "benchmark-elasticsearch")` – Specifies the name for this database connection. This is specified as part of the URL.
- `plugin_name` `(string: "elasticsearch-database-plugin")` - Specifies the name of the plugin to use for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified during initial configuration. Defaults to true.
- `allowed_roles` `(list: [])` - List of the roles allowed to use this connection. Defaults to empty (no roles), if contains a `*` any role can use this connection.
- `root_rotation_statements` `(list: [])` - Specifies the database statements to be
  executed to rotate the root user's credentials. See the plugin's API page for more
  information on support and formatting for this parameter.
- `password_policy` `(string: "")` - The name of the
  [password policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies) to use when generating passwords
  for this database. If not specified, this will use a default policy defined as:
  20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.
- `url` `(string: <required>)` - The URL for Elasticsearch's API (`http://localhost:9200`).
- `username` `(string: <required>)` - The username to be used in the connection URL (`vault`). This can also be provided via the `VAULT_BENCHMARK_ELASTICSEARCH_USERNAME` environment variable.
- `password` `(string: <required>)` - The password to be used in the connection URL (`pa55w0rd`). This can also be provided via the `VAULT_BENCHMARK_ELASTICSEARCH_PASSWORD` environment variable.
- `ca_cert` `(string: "")` - The path to a PEM-encoded CA cert file to use to verify the Elasticsearch server's identity.
- `ca_path` `(string: "")` - The path to a directory of PEM-encoded CA cert files to use to verify the Elasticsearch server's identity.
- `client_cert` `(string: "")` - The path to the certificate for the Elasticsearch client to present for communication.
- `client_key` `(string: "")` - The path to the key for the Elasticsearch client to use for communication.
- `tls_server_name` `(string: "")` - This, if set, is used to set the SNI host when connecting via TLS.
- `insecure` `(bool: false)` - Not recommended. Default to `false`. Can be set to `true` to disable certificate verification.
- `username_template` `(string)` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how dynamic usernames are generated.
- `use_old_xpack` `(bool: false)` - Can be set to `true` to use the `/_xpack/security` base API path when managing Elasticsearch. May be required for Elasticsearch server versions prior to 6.

### Role Config `role`

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` `(string: "benchmark-elasticsearch")` - The name of the database connection to use for this role.
- `default_ttl` `(string: "")` - Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (`1h`) or an integer number of seconds. Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` - Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (`1h`) or an integer number of seconds. Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](https://developer.hashicorp.com/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(list)` – Specifies the database
  statements executed to create and configure a user. See the plugin's API page
  for more information on support and formatting for this parameter.

## Example Configuration

```hcl
test "elasticsearch_secret" "elasticsearch_test_1" {
    weight = 100
    config {
        db_connection {
            url = "https://localhost:9200"
            username = "elastic"
            password = "pass"
        }
        role {
            creation_statements = ["{\"elasticsearch_role_definition\": {\"indices\": [{\"names\":[\"*\"], \"privileges\":[\"read\"]}]}}"]
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-05-01T12:57:50.575-0500 [INFO]  vault-benchmark: setting up targets
2023-05-01T12:57:50.713-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-05-01T12:57:52.902-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                   count  rate       throughput  mean          95th%        99th%         successRatio
elasticsearch_test1  107    52.860797  48.892726   197.742375ms  291.00526ms  382.716563ms  100.00%
```
