# MongoDB Atlas Secrets Engine Benchmark

This benchmark will test the dynamic generation of MongoDB Atlas credentials.

## Test Parameters

### MongoDB Atlas Database Configuration `db_connection`

- `name` `(string: "benchmark-mongodb-atlas")` – Specifies the name for this database
  connection. This is specified as part of the URL.
- `plugin_name` `(string: mongodbatlas-database-plugin)` - Specifies the name of the plugin to use
  for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified
  during initial configuration. Defaults to true.
- `allowed_roles` `(list: [])` - List of the roles allowed to use this connection.
  Defaults to empty (no roles), if contains a `*` any role can use this connection.
- `public_key` `(string: <required>)` – The Public Programmatic API Key used to authenticate with the MongoDB Atlas API. This can also be provided via the `VAULT_BENCHMARK_MONGODB_ATLAS_PUBLIC_KEY` environment variable.
- `private_key` `(string: <required>)` - The Private Programmatic API Key used to connect with MongoDB Atlas API. This can also be provided via the `VAULT_BENCHMARK_MONGODB_ATLAS_PRIVATE_KEY` environment variable.
- `project_id` `(string: <required>)` - The [Project ID](https://www.mongodb.com/docs/atlas/api/#project-id) the Database User should be created within.
- `username_template` `(string)` - Template describing how dynamic usernames are generated.

### Role Config

- `name` `(string: "benchmark-role")` – Specifies the name of the role to create. This
  is specified as part of the URL.
- `db_name` `(string: "benchmark-mongo")` - The name of the database connection to use
  for this role.
- `default_ttl` `(string: "")` - Specifies the TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`) or an integer
  number of seconds. Defaults to system/engine default TTL time.
- `max_ttl` `(string: "")` - Specifies the maximum TTL for the leases
  associated with this role. Accepts time suffixed strings (`1h`) or an integer
  number of seconds. Defaults to `sys/mounts`'s default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer. See also [The TTL General Case](https://developer.hashicorp.com/vault/docs/concepts/tokens#the-general-case).
- `creation_statements` `(string)` – Specifies the database
  statements executed to create and configure a user. Must be a
  serialized JSON object, or a base64-encoded serialized JSON object.
  The object can optionally contain a `database_name`, the name of
  the authentication database to log into MongoDB. In Atlas deployments of
  MongoDB, the options for the authentication database include admin (default) and $external database.
  The object must also contain a `roles` array, and from Vault version 1.6.0 (plugin
  version 0.2.0) may optionally contain a `scopes` array. The `roles` array
  contains objects that hold a series of roles `roleName`, an optional

## Example Configuration

```hcl
test "mongodb_atlas_secret" "mongodb_atlas_secret_test_1" {
    weight = 100
    config {
        db_connection {
            public_key = "PUBILC_KEY"
            private_key = "PRIVATE_KEY"
            project_id = "PROJECT_ID"
        }
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-08-14T12:52:45.035-0400 [INFO]  vault-benchmark: setting up targets
2023-08-14T12:52:45.040-0400 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-08-14T12:52:49.222-0400 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                           count  rate      throughput  mean          95th%         99th%         successRatio
mongodb_atlas_secret_test_1  21     9.873511  5.021741    1.618011815s  2.137313314s  2.152995625s  100.00%
```
