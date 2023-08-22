# LDAP Dynamic Secret Benchmark `ldap_dynamic_secret`

This benchmark will test the dynamic generation of LDAP credentials.

## Test Parameters

### Secret Configuration `secret`

- `binddn` `(string: <required>)` - Distinguished name (DN) of object to bind for managing user entries. For example, `cn=vault,ou=Users,dc=hashicorp,dc=com`.
- `bindpass` `(string: <required>)` - Password to use along with `binddn` for managing user entries.  This can also be provided via the `VAULT_BENCHMARK_LDAP_BIND_PASS` environment variable.
- `url` `(string: "ldap://127.0.0.1")` - The LDAP server to connect to. Examples: `ldaps://ldap.myorg.com`, `ldaps://ldap.myorg.com:636`. This can also be a comma-delineated list of URLs, e.g. `ldaps://ldap.myorg.com, ldaps://ldap.myorg.com:636`, in which case the servers will be tried in-order if there are errors during the connection process.`.
- `password_policy` `(string: <optional>)` - The name of the [password policy](https://developer.hashicorp.com/vault/docs/concepts/password-policies) to use to generate passwords. Note that this accepts the name of the policy, not the policy itself.
- `schema` `(string: "openldap")` - The LDAP schema to use when storing entry passwords. Valid schemas include `openldap`, `ad`, and `racf`.
- `userdn` `(string: <optional>)` - The base DN under which to perform user search in [library management](https://developer.hashicorp.com/vault/api-docs/secret/ldap#library-management) and [static roles](https://developer.hashicorp.com/vault/api-docs/secret/ldap#static-roles). For example, `ou=Users,dc=hashicorp,dc=com`.
- `userattr` `(string: <optional>)` – The attribute field name used to perform user search in [library management](https://developer.hashicorp.com/vault/api-docs/secret/ldap#library-management) and [static roles](https://developer.hashicorp.com/vault/api-docs/secret/ldap#static-roles). Defaults to `cn` for the `openldap` schema, `userPrincipalName` for the `ad` schema, and `racfid` for the `racf` schema.
- `upndomain` (string: `optional`) - The domain (userPrincipalDomain) used to construct a UPN string for authentication. The constructed UPN will appear as `[binddn]@[upndomain]`. For example, if `upndomain=example.com` and `binddn=admin`, the UPN string `admin@example.com` will be used to log in to Active Directory.
- `connection_timeout` `(integer: 30)` - Timeout, in seconds, when attempting to connect to the LDAP server before trying the next URL in the configuration.
- `request_timeout` `(integer: 90)` - Timeout, in seconds, for the connection when making requests against the server before returning back an error.
- `starttls` `(bool: <optional>)` - If true, issues a `StartTLS` command after establishing an unencrypted connection. - `insecure_tls` `(bool: <optional>)` - If true, skips LDAP server SSL certificate verification - insecure, use with caution!
- `certificate` `(string: <optional>)` - CA certificate to use when verifying LDAP server certificate, must be x509 PEM encoded.
- `client_tls_cert` `(string: <optional>)` - Client certificate to provide to the LDAP server, must be x509 PEM encoded.
- `client_tls_key` `(string: <optional>)` - Client key to provide to the LDAP server, must be x509 PEM encoded.

### Role Configuration `role`

- `role_name` `(string: "benchmark-role")` - The name of the dynamic role.
- `creation_ldif` `(string: <required>)` - A templatized LDIF string used to create a user account. This may contain multiple LDIF entries. The `creation_ldif` can also be used to add the user account to an **_existing_** group. All LDIF entries are performed in order. If Vault encounters an error while executing the `creation_ldif` it will stop at the first error and not execute any remaining LDIF entries. If an error occurs and `rollback_ldif` is specified, the LDIF entries in `rollback_ldif` will be executed. See `rollback_ldif` for more details. This field may optionally be provided as a base64 encoded string.
- `deletion_ldif` `(string: <required>)` - A templatized LDIF string used to delete the user account once its TTL has expired. This may contain multiple LDIF entries. All LDIF entries are performed in order. If Vault encounters an error while executing an entry in the `deletion_ldif` it will attempt to continue executing any remaining entries. This field may optionally be provided as a base64 encoded string.
- `rollback_ldif` `(string: <not required but recommended>)` - A templatized LDIF string used to attempt to rollback any changes in the event that execution of the `creation_ldif` results in an error. This may contain multiple LDIF entries. All LDIF entries are performed in order. If Vault encounters an error while executing an entry in the `rollback_ldif` it will attempt to continue executing any remaining entries. This field may optionally be provided as a base64 encoded string.
- `username_template` `(string: <optional>)` - A template used to generate a dynamic username. This will be used to fill in the `.Username` field within the `creation_ldif` string.
- `default_ttl` `(int: <optional>)` - Specifies the TTL for the leases associated with this role. Defaults to system/engine default TTL time.
- `max_ttl` `(int: <optional>)` - Specifies the maximum TTL for the leases associated with this role. Defaults to system/mount default TTL time; this value is allowed to be less than the mount max TTL (or, if not set, the system max TTL), but it is not allowed to be longer.

## Example HCL

```hcl
test "ldap_dynamic_secret" "ldap_secret_test1" {
    weight = 100
    config {
        secret {
            url         = "ldap://localhost"
            binddn      = "cn=admin,dc=hashicorp,dc=com"
            bindpass    = "admin"
        }
        role  {
            creation_ldif = "ZG46IGNuPXt7LlVzZXJuYW1lfX0sb3U9dXNlcnMsZGM9aGFzaGljb3JwLGRjPWNvbQpvYmplY3RDbGFzczogcGVyc29uCm9iamVjdENsYXNzOiB0b3AKY246IGxlYXJuCnNuOiB7ey5QYXNzd29yZCB8IHV0ZjE2bGUgfCBiYXNlNjR9fQptZW1iZXJPZjogY249ZGV2LG91PWdyb3VwcyxkYz1oYXNoaWNvcnAsZGM9Y29tCnVzZXJQYXNzd29yZDoge3suUGFzc3dvcmR9fQo="
            deletion_ldif = "ZG46IGNuPXt7LlVzZXJuYW1lfX0sb3U9dXNlcnMsZGM9aGFzaGljb3JwLGRjPWNvbQpjaGFuZ2V0eXBlOiBkZWxldGUK"
            rollback_ldif = "ZG46IGNuPXt7LlVzZXJuYW1lfX0sb3U9dXNlcnMsZGM9aGFzaGljb3JwLGRjPWNvbQpjaGFuZ2V0eXBlOiBkZWxldGUK"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-04-26T18:11:50.901-0500 [INFO]  vault-benchmark: setting up targets
2023-04-26T18:11:50.918-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-26T18:11:52.920-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op               count  rate         throughput  mean        95th%       99th%       successRatio
ldap_secret_test1  13345  6671.750122  0.000000    1.495695ms  2.128745ms  3.542841ms  100.00%
```
