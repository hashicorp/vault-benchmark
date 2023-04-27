# Certification Authentication Benchmark (`cert_auth`) 
This benchmark tests the performance of logins using the Certificate auth method.

## Benchmark Configuration Parameters
- `name` `(string: "benchmark-vault")` - The name of the certificate role.
- `certificate` `(string)` - The PEM-format CA certificate.
- `allowed_names` `(string: "")` - DEPRECATED: Please use the individual
  `allowed_X_sans` parameters instead. Constrain the Common and Alternative
  Names in the client certificate with a [globbed pattern](https://github.com/ryanuber/go-glob/blob/master/README.md#example). Value is
  a comma-separated list of patterns. Authentication requires at least one Name
  matching at least one pattern. If not set, defaults to allowing all names.
- `allowed_common_names` `(array: [])` - Constrain the Common
  Names in the client certificate with a [globbed pattern](https://github.com/ryanuber/go-glob/blob/master/README.md#example). Value is
  a comma-separated list of patterns. Authentication requires at least one Name
  matching at least one pattern. If not set, defaults to allowing all names.
- `allowed_dns_sans` `(array: [])` - Constrain the Alternative
  Names in the client certificate with a [globbed pattern](https://github.com/ryanuber/go-glob/blob/master/README.md#example). Value is
  a comma-separated list of patterns. Authentication requires at least one DNS
  matching at least one pattern. If not set, defaults to allowing all dns.
- `allowed_email_sans` `(array: [])` - Constrain the Alternative
  Names in the client certificate with a [globbed pattern](https://github.com/ryanuber/go-glob/blob/master/README.md#example). Value is
  a comma-separated list of patterns. Authentication requires at least one
  Email matching at least one pattern. If not set, defaults to allowing all
  emails.
- `allowed_uri_sans` `(array: [])` - Constrain the Alternative
  Names in the client certificate with a [globbed pattern](https://github.com/ryanuber/go-glob/blob/master/README.md#example). Value is
  a comma-separated list of URI patterns. Authentication requires at least one
  URI matching at least one pattern. If not set, defaults to allowing all URIs.
- `allowed_organizational_units` `(array: [])` - Constrain the
  Organizational Units (OU) in the client certificate with a [globbed pattern](https://github.com/ryanuber/go-glob/blob/master/README.md#example). Value is
  a comma-separated list of OU patterns. Authentication requires at least one
  OU matching at least one pattern. If not set, defaults to allowing all OUs.
- `required_extensions` `(array: [])` - Require specific Custom
  Extension OIDs to exist and match the pattern. Value is a comma separated
  string or array of `oid:value`. Expects the extension value to be some type
  of ASN1 encoded string. All conditions _must_ be met. Supports globbing on
  `value`.
- `allowed_metadata_extensions` `(array:[])` - A comma separated string or
  array of oid extensions. Upon successful authentication, these extensions
  will be added as metadata if they are present in the certificate. The
  metadata key will be the string consisting of the oid numbers separated
  by a dash (-) instead of a dot (.) to allow usage in ACL templates.
- `display_name` `(string: "")` - The `display_name` to set on tokens issued
  when authenticating against this CA certificate. If not set, defaults to the
  name of the role.
- `token_ttl` `(string: "")` - The incremental lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_max_ttl` `(string: "")` - The maximum lifetime for
  generated tokens. This current value of this will be referenced at renewal
  time.
- `token_policies` `(array: [])` - List of
  token policies to encode onto generated tokens. Depending on the auth method, this
  list may be supplemented by user/group/other values.
- `policies` `(array: [])` - DEPRECATED: Please
  use the `token_policies` parameter instead. List of token policies to encode
  onto generated tokens. Depending on the auth method, this list may be
  supplemented by user/group/other values.
- `token_bound_cidrs` `(array: [])` - List of
  CIDR blocks; if set, specifies blocks of IP addresses which can authenticate
  successfully, and ties the resulting token to these blocks as well.
- `token_explicit_max_ttl` `(string: "")` - If set, will encode
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
- `token_period` `(string: "")` - The maximum allowed [period](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls) value when a periodic token is requested from this role.
- `token_type` `(string: "")` - The type of token that should be generated. Can
  be `service`, `batch`, or `default` to use the mount's tuned default (which
  unless changed will be `service` tokens). For token store roles, there are two
  additional possibilities: `default-service` and `default-batch` which specify
  the type to return unless the client requests a different type at generation
  time.

## Example HCL 
```
test "cert_auth" "cert_auth_test1" {
	weight = 25
	config {
		name = "test"
    certificate = cert.pem
	}
}
```

## Example Usage
```bash
$ vault-benchmark run -config=config.hcl 
2023-04-26T14:50:27.124-0500 [INFO]  vault-benchmark: setting up targets
2023-04-26T14:50:27.135-0500 [INFO]  vault-benchmark: starting benchmarks: duration=3s
2023-04-26T14:50:30.136-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op               count  rate         throughput  mean        95th%      99th%       successRatio
cert_auth_test1  22203  7401.042556  0.000000    1.348606ms  1.84933ms  2.458901ms  0.00%
```
