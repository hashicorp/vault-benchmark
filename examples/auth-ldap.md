# LDAP Auth Benchmark `ldap_auth`
This benchmark will test LDAP Authentication to Vault. In order to use this test, configuration for the target LDAP server(s) must be provided as a JSON file using the `ldap_config_json` flag. The primary required fields are `url` and `groupdn` depending on the LDAP environment setup and desired connection method.

## Test Parameters
### Auth Configuration `auth`
- `url` `(string: <required>)` – The LDAP server to connect to. Examples:
  `ldap://ldap.myorg.com`, `ldaps://ldap.myorg.com:636`. Multiple URLs can be
  specified with commas, e.g. `ldap://ldap.myorg.com,ldap://ldap2.myorg.com`;
  these will be tried in-order.
- `case_sensitive_names` `(bool: false)` – If set, user and group names
  assigned to policies within the backend will be case sensitive. Otherwise,
  names will be normalized to lower case. Case will still be preserved when
  sending the username to the LDAP server at login time; this is only for
  matching local user/group definitions.
- `request_timeout` `(integer: 90)` - Timeout, in seconds, for
  the connection when making requests against the server before returning back
  an error.
- `starttls` `(bool: false)` – If true, issues a `StartTLS` command after
  establishing an unencrypted connection.
- `tls_min_version` `(string: "tls12")` – Minimum TLS version to use. Accepted
  values are `tls10`, `tls11`, `tls12` or `tls13`.
- `tls_max_version` `(string: "tls12")` – Maximum TLS version to use. Accepted
  values are `tls10`, `tls11`, `tls12` or `tls13`.
- `insecure_tls` `(bool: false)` – If true, skips LDAP server SSL certificate
  verification - insecure, use with caution!
- `certificate` `(string: "")` – CA certificate to use when verifying LDAP server
  certificate, must be x509 PEM encoded.
- `client_tls_cert` `(string "")` - Client certificate to provide to the LDAP
  server, must be x509 PEM encoded (optional).
- `client_tls_key` `(string "")` - Client certificate key to provide to the LDAP
  server, must be x509 PEM encoded (optional).
- `binddn` `(string: "")` – Distinguished name of object to bind when performing
  user search. Example: `cn=vault,ou=Users,dc=example,dc=com`
- `bindpass` `(string: "")` – Password to use along with `binddn` when performing
  user search. This can also be provided via the `VAULT_BENCHMARK_LDAP_BIND_PASS` environment variable.
- `userdn` `(string: "")` – Base DN under which to perform user search. Example:
  `ou=Users,dc=example,dc=com`
- `userattr` `(string: "cn")` – Attribute on user attribute object matching the
  username passed when authenticating. Examples: `sAMAccountName`, `cn`, `uid`
- `discoverdn` `(bool: false)` – Use anonymous bind to discover the bind DN of a
  user.
- `deny_null_bind` `(bool: true)` – This option prevents users from bypassing
  authentication when providing an empty password.
- `upndomain` `(string: "")` – The userPrincipalDomain used to construct the UPN
  string for the authenticating user. The constructed UPN will appear as
  `[username]@UPNDomain`. Example: `example.com`, which will cause vault to bind
  as `username@example.com`.
- `userfilter` `(string: "")` – An optional LDAP user search filter.
  The template can access the following context variables: UserAttr, Username.
  The default is `({{.UserAttr}}={{.Username}})`, or `({{.UserAttr}}={{.Username@.upndomain}})`
  if `upndomain` is set.
- `anonymous_group_search` `(bool: false)` - Use anonymous binds when performing
  LDAP group searches (note: even when `true`, the initial credentials will still
  be used for the initial connection test).
- `groupfilter` `(string: "")` – Go template used when constructing the group
  membership query. The template can access the following context variables:
  \[`UserDN`, `Username`\]. The default is
  `(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))`,
  which is compatible with several common directory schemas. To support
  nested group resolution for Active Directory, instead use the following
  query: `(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))`.
- `groupdn` `(string: "")` – LDAP search base to use for group membership
  search. This can be the root containing either groups or users. Example:
  `ou=Groups,dc=example,dc=com`
- `groupattr` `(string: "")` – LDAP attribute to follow on objects returned by
  `groupfilter` in order to enumerate user group membership. Examples: for
  groupfilter queries returning _group_ objects, use: `cn`. For queries
  returning _user_ objects, use: `memberOf`. The default is `cn`.
- `username_as_alias` `(bool: false)` - If set to true, forces the auth method
  to use the username passed by the user as the alias name.
- `token_ttl` `(integer: 0)` - The incremental lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_max_ttl` `(integer: 0)` - The maximum lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_policies` `(array: [])` - List of
  token policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.
- `token_bound_cidrs` `(array: [])` - List of
  CIDR blocks; if set, specifies blocks of IP addresses which can authenticate
  successfully, and ties the resulting token to these blocks as well.
- `token_explicit_max_ttl` `(integer: 0)` - If set, will encode
  an [explicit max
  TTL](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls)
  onto the token. This is a hard cap even if `token_ttl` and `token_max_ttl`
  would otherwise allow a renewal.
- `token_no_default_policy` `(bool: false)` - If set, the `default` policy will
  not be set on generated tokens; otherwise it will be added to the policies set
  in `token_policies`.
- `token_num_uses` `(integer: 0)` - The maximum number of times a generated
  token may be used (within its lifetime); 0 means unlimited.
  If you require the token to have the ability to create child tokens,
  you will need to set this value to 0.
- `token_period` `(integer: 0)` - The maximum allowed [period](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) value when a periodic token is requested from this role.
- `token_type` `(string: "")` - The type of token that should be generated. Can
  be `service`, `batch`, or `default` to use the mount's tuned default (which
  unless changed will be `service` tokens). For token store roles, there are two
  additional possibilities: `default-service` and `default-batch` which specify
  the type to return unless the client requests a different type at generation
  time.

### Test User Config `role`
- `username` `(string: "")`: ldap test username. This can also be provided via the
`VAULT_BENCHMARK_LDAP_TEST_USERNAME` environment variable.
- `password` `(string: "")`: ldap test password. This can also be provided via the
`VAULT_BENCHMARK_LDAP_TEST_PASSWORD` environment variable.

## Example HCL
```
test "ldap_auth" "ldap_auth_test1" {
    weight = 100
    config {
        auth {
            url         = "ldap://localhost"
            userdn      = "ou=users,dc=hashicorp,dc=com"
            groupdn     = "ou=groups,dc=hashicorp,dc=com"
            binddn      = "cn=admin,dc=hashicorp,dc=com"
            bindpass    = "admin"
            userattr    = "uid"
            group_attr   = "cn"
            group_filter = "(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))"
            token_policies = ["default","test"]
        }
        test_user  {
            username = "alice"
            password = "password"
        }
    }
}
```

## Example Usage
```
$ vault-benchmark run -config=config.hcl                   18:11:35
2023-04-26T18:11:50.901-0500 [INFO]  vault-benchmark: setting up targets
2023-04-26T18:11:50.918-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-26T18:11:52.920-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op               count  rate         throughput  mean        95th%       99th%       successRatio
ldap_auth_test1  13345  6671.750122  0.000000    1.495695ms  2.128745ms  3.542841ms  100.00%
```