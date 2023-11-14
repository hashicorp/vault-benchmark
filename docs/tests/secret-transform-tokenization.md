# Transform Tokenization Configuration Options

This benchmark will test Vault's Transform secrets engine by performing Tokenization encoding on provided input.

## Test Parameters

### Role Config `role`

- `name` `(string: "benchmark-role")` –
  Specifies the name of the role to create. This is part of the request URL.

- `transformations` (`list: ["benchmarktransformation"]`) -
  Specifies the transformations that can be used with this role.

### Tokenization Config `tokenization`

- `name` `(string: "benchmarktransformation")` –
  Specifies the name of the transformation to create or update. This is part of
  the request URL.

- `mapping_mode` `(string: "default")` -
  Specifies the mapping mode for stored tokenization values. `default`
  is strongly recommended for highest security. `exportable` allows
  for all plaintexts to be decoded via the export-decoded endpoint
  in an emergency.

- `max_ttl`: `(duration: "0")` -
  The maximum TTL of a token. If 0 or unspecified, tokens may have no expiration.

- `allowed_roles` `(list: ["benchmark-role"])` -
  Specifies a list of allowed roles that this transformation can be assigned to.
  A role using this transformation must exist in this list in order for
  encode and decode operations to properly function.

- `stores` `(list: ["builtin/internal"])` -
  The list of tokenization stores to use for tokenization state. Vault's
  internal storage is used by default.

- `deletion_allowed` `(bool: false)` -
  If true, this transform can be deleted. Otherwise deletion is blocked while this
  value remains false. Note that deleting the transform deletes the underlying key
  making decoding of tokenized values impossible without restoring from a backup.

### Store Config `store`

- `name` `(string: <required>)` –
  Specifies the name of the store to create or update. This is part of
  the request URL.

- `type` `(string: <required>)` -
  Specifies the type of store. Currently only `sql` is supported.

- `driver` `(string: <required>)` -
  Specifies the database driver to use, and thus which SQL database type.
  Currently the supported options are `postgres`, `mysql`, and `mssql`.

- `connection_string` `(string: <required>)` -
  A database connection string with template slots for username and password that
  Vault will use for locating and connecting to a database. Each
  database driver type has a different syntax for its connection strings.

  > When using MySQL, make sure to append `?parseTime=true` to enable timestamp parsing.

- `username`: `(string: <required>)` -
  The username value to use when connecting to the database.

- `password`: `(string: <required>)` -
  The password value to use when connecting to the database.

- `supported_transformations:`(list: ["tokenization"])`The types of transformations this store can host. Currently only`tokenization`
  is supported.

- `schema`: `(string: "public")` -
  The schema within the database to expect tokenization state tables.

- `max_open_connections` `(int: 4)` -
  The maximum number of connections to the database at any given time.

- `max_idle_connections` `(int: 4)` -
  The maximum number of idle connections to the database at any given time.

- `max_connection_lifetime` `(duration: 0)` -
  The maximum amount of time a connection can be open before closing it.
  0 means no limit. Uses [duration format strings](/docs/concepts/duration-format).

- `pct_couchbase_read`: percent of requests that are Couchbase dynamic credential generations

### Store Schema Config `store_schema`

- `name` `(string: <required>)` –
  Specifies the name of the store to create or update. This is part of
  the request URL.

- `username`: `(string: <required>)` -
  The username value to use when connecting to the database.

- `password`: `(string: <required>)` -
  The password value to use when connecting to the database.

- `transformation_type`: `(string: "tokenization")` -
  The transformation type. Currently only `tokenization` is supported.

### Encode Input `input`

- `role_name` `(string: "benchmark-role)` –
  Specifies the role name to use for this operation. This is specified as part
  of the URL.

- `value` `(string: "123456789")` –
  Specifies the value to be encoded.

- `transformation` `(string: "benchmarktransformation")` –
  Specifies the transformation within the role that should be used for this
  encode operation. If a single transformation exists for role, this parameter
  may be skipped and will be inferred. If multiple transformations exist, one
  must be specified.

- `ttl` `(duration "0")` -
  Specifies the TTL of the resulting token. Only applicable for tokenization
  transformations.

- `metadata` `(string)` -
  For tokenization transforms, a list of key value pairs of the form
  `key1=value1,key2=value2,`... These optional metadata values will be
  stored with the value and can be retrieved with the
  [metadata](#retrieve-token-metadata) endpoint.

- `tweak` `(string)` –
  Specifies the **base64 encoded** tweak to use. Only applicable for FPE
  transformations with `supplied` as the tweak source. The tweak must be a
  7-byte value that is then base64 encoded.

- `reference` `(string: "")` -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using ‘batch_input’ below.

- `batch_input` `(array<object>: nil)` -
  Specifies a list of items to be encoded in a single batch. When this
  parameter is set, the 'value', 'transformation', 'ttl', 'tweak' and
  'reference' parameters are ignored. Instead, the aforementioned parameters
  should be provided within each object in the list.

  ```json
  [
    {
      "value": "1111-1111-1111-1111",
      "transformation": "ccn-fpe"
    },
    {
      "value": "2222-2222-2222-2222",
      "transformation": "ccn-masking",
      "reference": "order#1234"
    },
    {
      "value": "3333-3333-3333-3333",
      "transformation": "ccn-tokenization",
      "ttl": "42d"
    }
  ]
  ```

### Example Configuration

```hcl
test "transform_tokenization" "tokenization_test1" {
 weight = 100
 config {
  input {
   ttl = "5s"
            value = "123456789"
  }
 }
}
```
