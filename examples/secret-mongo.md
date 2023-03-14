# MongoDB Secret Configuration Options

This benchmark will test the dynamic generation of MongoDB credentials.

## Test Parameters

### MongoDB Config

- `name` _(string: <required>)_: Specifies the name for this database connection. This is specified as part of the URL.
- `plugin_name` _(string: "mongodb-database-plugin")_: Specifies the name of the plugin to use for this connection.
- `allowed_roles` _(list: ["benchmark-role"])_: List of the roles allowed to use this connection. If contains a * any role can use this connection.
- `connection_url` _(string: <required>)_: Specifies the connection string used to connect to the database.
- `username` _(string: <required>)_: Specifies the name of the user to use as the "root" user when connecting to the database. This "root" user is used to create/update/delete users managed by these plugins, so you will need to ensure that this user has permissions to manipulate users appropriate to the database.
- `password` _(string: <required>)_: Specifies the password to use when connecting with the `username`.

### Role Config

- `name` _(string: "benchmark-role")_: Specifies the name of the role to create. This is specified as part of the URL.
- `db_name` _(string: <required>)_: The name of the database connection to use for this role.
- `default_ttl` _(string: "1h")_: Specifies the TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds.
- `max_ttl` _(string: "24h")_: Specifies the maximum TTL for the leases associated with this role. Accepts time suffixed strings (1h) or an integer number of seconds.
- `creation_statements` _(list: [])_: Specifies the database statements executed to create and configure a user.  Defaults to `"{ "db": "admin", "roles": [{ "role": "readWrite" }, {"role": "read", "db": "foo"}] }"`

## Example Configuration

```hcl
test "mongodb_secret" "mongodb_test_1" {
    weight = 100
    config {
        mongodb_config {
            name = "mongo-benchmark-database"
            connection_url = "mongodb://{{username}}:{{password}}@127.0.0.1:27017/admin?tls=false"
            username = "mdbadmin"
            password = "root"
        }
        role_config {
            db_name = "mongo-benchmark-database"
        }
    }
}
```

### Example Usage

```bash
$ vault-benchmark run -config=example-configs/mongodb/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate       throughput  mean          95th%         99th%         successRatio
mongodb_test_1  473    47.284284  46.300585   213.963008ms  222.443684ms  228.1842ms  100.00%
```
