# KMIP Secrets Engine Benchmark (`kmip_secret`)

This benchmark will test the dynamic generation of KMIP credentials.

## Test Parameters

NOTE: It is recommended to set the `cleanup` parameter in the global configuration options
to `true` if you plan on running this benchmark multiple times.

### DB Connection Configuration `kmip`

- `listen_addrs` (`list: ["127.0.0.1:5696"] || string`) - Address and port the
  KMIP server should listen on. Can be given as a JSON list or a
  comma-separated string list. If multiple values are given, all will be
  listened on.
- `connection_timeout` (`int: 1 || string:"1s"`) - Duration in either an integer
  number of seconds (10) or an integer time unit (10s) within which connections
  must become ready.
- `server_hostnames` (`list: ["localhost"] || string`) - Hostnames to include in
  the server's TLS certificate as SAN DNS names. The first will be used as the
  common name (CN).
- `server_ips` (`list: [] || string`) - IPs to include in the server's TLS
  certificate as SAN IP addresses. Localhost (IPv4 and IPv6) will be automatically
  included.
- `tls_ca_key_type` (`string: "ec"`) - CA key type, `rsa` or `ec`.
- `tls_ca_key_bits` (`int: 521`) - CA key bits, valid values depend on key type.
- `tls_min_version` (`string: "tls12"`) - Minimum TLS version to accept.
- `default_tls_client_key_type` (`string: "ec"`): - Client certificate key type,
  `rsa` or `ec`.
- `default_tls_client_key_bits` (`int: 521`): - Client certificate key bits, valid
  values depend on key type.
- `default_tls_client_ttl` (`int: 86400 || string:"24h"`) – Client certificate
  TTL in either an integer number of seconds (10) or an integer time unit (10s).

### Role Configuration `role`

- `scope` (`string: <required>`) - Name of scope. This is part of the request URL.
- `role` (`string: <required>`) - Name of role. This is part of the request URL.
- `tls_client_key_type` (`string`): - Client certificate key type,
  `rsa` or `ec`. Overrides engine-wide default managed in `config` endpoint.
- `tls_client_key_bits` (`int`): - Client certificate key bits, valid
  values depend on key type. Overrides engine-wide default managed in `config`
  endpoint.
- `tls_client_ttl` (`int or string`) – Client certificate
  TTL in either an integer number of seconds (10) or an integer time unit (10s).
  Overrides engine-wide default managed in `config` endpoint.
- `operation_none` (`bool: false`) - Remove all permissions
  from this role. May not be specified with any other
  `operation_` params.
- `operation_all` (`bool: false`) - Grant all permissions
  to this role. May not be specified with any other
  `operation_` params.
- `operation_activate` (`bool: false`) - Grant permission to use the KMIP
  `Activate` operation.
- `operation_add_attribute` (`bool: false`) - Grant permission to use the KMIP
  `Add Attribute` operation.
- `operation_create` (`bool: false`) - Grant permission to use the KMIP
  `Create` operation.
- `operation_decrypt` (`bool: false`) - Grant permission to use the KMIP
  `Decrypt` operation.
- `operation_destroy` (`bool: false`) - Grant permission to use the KMIP
  `Destroy` operation.
- `operation_discover_versions` (`bool: false`) - Grant permission to use the KMIP
  `Discover Versions` operation.
- `operation_encrypt` (`bool: false`) - Grant permission to use the KMIP
  `Encrypt` operation.
- `operation_get` (`bool: false`) - Grant permission to use the KMIP
  `Get` operation.
- `operation_get_attribute_list` (`bool: false`) - Grant permission to use the KMIP
  `Get Attribute List` operation.
- `operation_get_attributes` (`bool: false`) - Grant permission to use the KMIP
  `Get Attributes` operation.
- `operation_import` (`bool: false`) - Grant permission to use the KMIP
  `Import` operation.
- `operation_locate` (`bool: false`) - Grant permission to use the KMIP
  `Locate` operation.
- `operation_query` (`bool: false`) - Grant permission to use the KMIP
  `Query` operation.
- `operation_register` (`bool: false`) - Grant permission to use the KMIP
  `Register` operation.
- `operation_rekey` (`bool: false`) - Grant permission to use the KMIP
  `Rekey` operation.
- `operation_revoke` (`bool: false`) - Grant permission to use the KMIP
  `Revoke` operation.

## Example Configuration

```hcl
test "kmip_secret" "kmip_test_1" {
    weight = 100
    config {
        kmip {
            listen_addrs = "0.0.0.0:5696"
            server_hostnames = "127.0.0.1"
        }
        role  {
            operation_all = true
        }
    }
}

```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-08-31T11:13:37.755-0400 [INFO]  vault-benchmark: setting up targets
2023-08-31T11:13:37.784-0400 [INFO]  vault-benchmark: starting benchmarks: duration=5s
2023-08-31T11:13:42.785-0400 [INFO]  vault-benchmark: cleaning up targets
2023-08-31T11:13:43.289-0400 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op           count  rate         throughput   mean       95th%       99th%       successRatio
kmip_test_1  5000   1000.232312  1000.086532  867.943µs  1.185636ms  2.577093ms  100.00%
```
