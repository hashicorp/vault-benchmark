# MongoDB Secrets Engine Benchmark

This benchmark will test the dynamic generation of MongoDB credentials.

## Test Parameters

### MongoDB Database Configuration `db_connection`

- `name` `(string: "benchmark-mongo")` – Specifies the name for this database
  connection. This is specified as part of the URL.
- `plugin_name` `(string: mongodb-database-plugin)` - Specifies the name of the plugin to use
  for this connection.
- `plugin_version` `(string: "")` - Specifies the semantic version of the plugin to use for this connection.
- `verify_connection` `(bool: true)` – Specifies if the connection is verified
  during initial configuration. Defaults to true.
- `allowed_roles` `(list: [])` - List of the roles allowed to use this connection.
  Defaults to empty (no roles), if contains a `*` any role can use this connection.
- `connection_url` `(string: <required>)` – Specifies the MongoDB standard
  connection string (URI). This field can be templated and supports passing the
  username and password parameters in the following format `{{field_name}}`. A
  templated connection URL is required when using root credential rotation.
- `write_concern` `(string: "")` - Specifies the MongoDB [write
  concern][mongodb-write-concern]. This is set for the entirety of the session,
  maintained for the lifecycle of the plugin process. Must be a serialized JSON
  object, or a base64-encoded serialized JSON object. The JSON payload values
  map to the values in the [Safe][mgo-safe] struct from the mgo driver.
- `username` `(string: <required>)` - The root credential username used in the connection URL. This can also be provided via the `VAULT_BENCHMARK_MONGODB_USERNAME` environment variable.
- `password` `(string: <required>)` - The root credential password used in the connection URL. This can also be provided via the `VAULT_BENCHMARK_MONGODB_PASSWORD` environment variable.
- `tls_certificate_key` `(string: "")` - x509 certificate for connecting to the database.
  This must be a PEM encoded version of the private key and the certificate combined.
- `tls_ca` `(string: "")` - x509 CA file for validating the certificate presented by the
  MongoDB server. Must be PEM encoded.
- `username_template` `(string)` - [Template](https://developer.hashicorp.com/vault/docs/concepts/username-templating) describing how
  dynamic usernames are generated.

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
  The object can optionally contain a `db` string for session connection,
  and must contain a `roles` array. This array contains objects that holds
  a `role`, and an optional `db` value, and is similar to the BSON document that
  is accepted by MongoDB's `roles` field. Vault will transform this array into
  such format. For more information regarding the `roles` field, refer to
  [MongoDB's documentation](https://docs.mongodb.com/manual/reference/method/db.createUser/).
- `revocation_statements` `(string)` – Specifies the database statements to
  be executed to revoke a user. Must be a serialized JSON object, or a base64-encoded
  serialized JSON object. The object can optionally contain a `db` string. If no
  `db` value is provided, it defaults to the `admin` database.

## Example Configuration

```hcl
test "mongodb_secret" "mongodb_test_1" {
    weight = 100
    config {
        db_connection {
            name = "mongo-benchmark-database"
            connection_url = "mongodb://{{username}}:{{password}}@127.0.0.1:27017/admin?tls=false"
            username = "mdbadmin"
            password = "root"
        }
        role {
            db_name = "mongo-benchmark-database"
        }
    }
}
```
