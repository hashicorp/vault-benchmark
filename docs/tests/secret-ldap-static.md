# LDAP Static Secret Benchmark `ldap_static_secret`

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

- `username` `(string: <required>)` - The username of the existing LDAP entry to manage password rotation for. LDAP search for the username will be rooted at the [userdn](/vault/api-docs/secret/ldap#userdn) configuration value. The attribute to use when searching for the user can be configured with the [userattr](/vault/api-docs/secret/ldap#userattr) configuration value. This is useful when `dn` isn't used for login purposes (such as SSH). Cannot be modified after creation.<br /> **Example:** `"bob"`
- `dn` `(string: <optional>)` - Distinguished name (DN) of the existing LDAP entry to manage password rotation for. If given, it will take precedence over `username` for the LDAP search performed during password rotation. Cannot be modified after creation.<br /> **Example:** `cn=bob,ou=Users,dc=hashicorp,dc=com`
- `rotation_period` `(string: <required>)` - How often Vault should rotate the password of the user entry. Accepts [duration format strings](/vault/docs/concepts/duration-format). The minimum rotation period is 5 seconds.<br /> **Example:** `"3600", "5s", "1h"`

## Example HCL

```hcl
test "ldap_static_secret" "ldap_static_secret2" {
    weight = 100
    config {
        secret {
            url         = "ldap://localhost"
            binddn      = "cn=admin,dc=hashicorp,dc=com"
            bindpass    = "admin"
        }
        role  {
            dn = "uid=alice,ou=users,dc=hashicorp,dc=com"
            username = "alice"
            rotation_period ="24h"
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
op                   count  rate         throughput  mean        95th%       99th%       successRatio
ldap_static_secret2  13345  6671.750122  0.000000    1.495695ms  2.128745ms  3.542841ms  100.00%
```
