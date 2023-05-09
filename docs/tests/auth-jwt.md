# Redis Static Credential Benchmark (`jwt_auth`)

This benchmark tests the performance of logins using the jwt auth method.

## Example HCL

```hcl
test "jwt_auth" "jwt_auth1" {
  weight = 100
  config {
    auth {
      jwks_url = "jwks.com"
    }

    role {
      name            = "my-jwt-role"
      role_type       = "jwt"
      bound_audiences = ["https://vault.plugin.auth.jwt.test"]
      user_claim      = "https://vault/user"
    }
  }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-04-26T17:52:03.294-0500 [INFO]  vault-benchmark: setting up targets
2023-04-26T17:52:03.320-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-04-26T17:52:05.322-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://localhost:8200
op         count  rate         throughput   mean        95th%       99th%       successRatio
jwt_auth1  8837   4418.525130  4416.285509  2.262041ms  3.135816ms  4.338269ms  100.00%
```

## Benchmark Configuration Parameters

### JWT Authentication Configuration (`auth`)`

- `oidc_discovery_url` `(string: <optional>)` - The OIDC Discovery URL, without any .well-known component (base path). Cannot be used with "jwks_url" or "jwt_validation_pubkeys".
- `oidc_discovery_ca_pem` `(string: <optional>)` - The contents of a CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used.
- `oidc_client_id` `(string: <optional>)` - The OAuth Client ID from the provider for OIDC roles.
- `oidc_client_secret` `(string: <optional>)` - The OAuth Client Secret from the provider for OIDC roles.
- `oidc_response_mode` `(string: <optional>)` - The response mode to be used in the OAuth2 request. Allowed values are "query" and "form_post". Defaults to "query". If using Vault namespaces, and oidc_response_mode is "form_post", then "namespace_in_state" should be set to false.
- `oidc_response_types` `(array of strings: <optional>)` - The response types to request. Allowed values are "code" and "id_token". Defaults to "code".
  Note: "id_token" may only be used if "oidc_response_mode" is set to "form_post".
- `jwks_url` `(string: <optional>)` - JWKS URL to use to authenticate signatures. Cannot be used with "oidc_discovery_url" or "jwt_validation_pubkeys".
- `jwks_ca_pem` `(string: <optional>)` - The contents of a CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.
- `jwt_validation_pubkeys` `(array of strings: <optional>)` - A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with "jwks_url" or "oidc_discovery_url".
- `bound_issuer` `(string: <optional>)` - The value against which to match the `iss` claim in a JWT.
- `jwt_supported_algs` `(array of strings: <optional>)` - A list of supported signing algorithms. Defaults to [RS256] for OIDC roles. Defaults to all [available algorithms](https://github.com/hashicorp/cap/blob/main/jwt/algs.go) for JWT roles.
- `default_role` `(string: <optional>)` - The default role to use if none is provided during login.
- `provider_config` `(string: <optional>)` - Configuration options for provider-specific handling. Providers with specific handling include: Azure, Google, SecureAuth, IBM ISAM. The options are described in each provider's section in [OIDC Provider Setup](https://developer.hashicorp.com/vault/docs/auth/jwt/oidc-providers).
- `namespace_in_state` `(bool: true)` - Pass namespace in the OIDC state parameter instead of as a separate query parameter. With this setting, the allowed redirect URL(s) in Vault and on the provider side should not contain a namespace query parameter. This means only one redirect URL entry needs to be maintained on the provider side for all vault namespaces that will be authenticating against it. Defaults to true for new configs.

### JWT Role Configuration (`role`)`

- `name` `(string: <required>)` - Name of the role.
- `role_type` `(string: <optional>)` - Type of role, either "oidc" (default) or "jwt".
- `bound_audiences` `(string: <optional>)` - a string `aud` claim to match against.
  Any match is sufficient. For "jwt" roles, at least one of `bound_audiences`, `bound_subject`,
  `bound_claims` or `token_bound_cidrs` is required. Optional for "oidc" roles.
- `user_claim` `(string: <required>)` - The claim to use to uniquely identify
  the user; this will be used as the name for the Identity entity alias created
  due to a successful login. The claim value must be a string.
- `user_claim_json_pointer` `(string: <optional>)` - Specifies if the `user_claim` value uses
  [JSON pointer](https://developer.hashicorp.com/vault/docs/auth/jwt#claim-specifications-and-json-pointer) syntax for
  referencing claims. By default, the `user_claim` value will not use JSON pointer.
- `clock_skew_leeway` `(int: <optional>)` - The amount of leeway to add to all claims to
  account for clock skew, in seconds. Defaults to `60` seconds if set to `0` and can be disabled
  if set to `-1`. Accepts an integer number of seconds, or a Go duration format string. Only applicable
  with "jwt" roles.
- `expiration_leeway` `(int: <optional>)` - The amount of leeway to add to expiration (`exp`) claims to
  account for clock skew, in seconds. Defaults to `150` seconds if set to `0` and can be disabled
  if set to `-1`. Accepts an integer number of seconds, or a Go duration format string. Only applicable
  with "jwt" roles.
- `not_before_leeway` `(int: <optional>)` - The amount of leeway to add to not before (`nbf`) claims to
  account for clock skew, in seconds. Defaults to `150` seconds if set to `0` and can be disabled
  if set to `-1`. Accepts an integer number of seconds, or a Go duration format string. Only applicable
  with "jwt" roles.
- `bound_subject` `(string: <optional>)` - If set, requires that the `sub`
  claim matches this value.
- `bound_claims` `(map: <optional>)` - If set, a map of claims (keys) to match against respective claim values (values).
  The expected value may be a single string or a list of strings. The interpretation of the bound
  claim values is configured with `bound_claims_type`. Keys support [JSON pointer](https://developer.hashicorp.com/vault/docs/auth/jwt#claim-specifications-and-json-pointer)
  syntax for referencing claims.
- `bound_claims_type` `(string: "string")` - Configures the interpretation of the bound_claims values.
  If `"string"` (the default), the values will treated as string literals and must match exactly.
  If set to `"glob"`, the values will be interpreted as globs, with `*` matching any number of
  characters.
- `groups_claim` `(string: <optional>)` - The claim to use to uniquely identify
  the set of groups to which the user belongs; this will be used as the names
  for the Identity group aliases created due to a successful login. The claim
  value must be a list of strings. Supports [JSON pointer](https://developer.hashicorp.com/vault/docs/auth/jwt#claim-specifications-and-json-pointer)
  syntax for referencing claims.
- `claim_mappings` `(map: <optional>)` - If set, a map of claims (keys) to be copied to
  specified metadata fields (values). Keys support [JSON pointer](https://developer.hashicorp.com/vault/docs/auth/jwt#claim-specifications-and-json-pointer)
  syntax for referencing claims.
- `oidc_scopes` `(list: <optional>)` - If set, a list of OIDC scopes to be used with an OIDC role.
  The standard scope "openid" is automatically included and need not be specified.
- `allowed_redirect_uris` `(list: <required>)` - The list of allowed values for redirect_uri
  during OIDC logins.
- `verbose_oidc_logging` `(bool: false)` - Log received OIDC tokens and claims when debug-level
  logging is active. Not recommended in production since sensitive information may be present
  in OIDC responses.
- `max_age` `(int: <optional>)` - Specifies the allowable elapsed time in seconds since the last
  time the user was actively authenticated with the OIDC provider. If set, the `max_age` request parameter
  will be included in the authentication request. See [AuthRequest](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
  for additional details. Accepts an integer number of seconds, or a Go duration format string.
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
