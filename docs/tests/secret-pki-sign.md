# PKI Sign Secret Configuration Options

This benchmark tests the performance of PKI signing operations.

## Example Configuration

```hcl
test "pki_sign" "pki_sign_test1" {
    weight = 100
    config {
        setup_delay="2s"
        root_ca {
            common_name = "benchmark.test"
        }
        intermediate_csr {
            common_name = "benchmark.test Intermediate Authority"
        }
        role {
            ttl = "10m"
        }
        sign {
            csr = "./MYCSR.csr"
        }
    }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
Setting up targets...
Starting benchmarks. Will run for 5s...
Benchmark complete!
Target: http://127.0.0.1:8200
op              count  rate         throughput   mean       95th%       99th%       successRatio
pki_sign_test1  10759  2151.124964  2149.133615  4.64791ms  6.081656ms  8.258573ms  100.00%
```

## Test Parameters

### Root CA Config `root`

- `type` `(string: "internal")` - Specifies the type of the root to
  create. If `exported`, the private key will be returned in the response; if
  `internal` the private key will not be returned and _cannot be retrieved
  later_; if `existing`, we use the value of the `key_ref` parameter to find
  existing key material to create the CSR; `kms` is also supported: [see managed keys](https://developer.hashicorp.com/vault/api-docs/secret/pki#managed-keys) for additional details. This parameter is part
  of the request URL.

- `issuer_name` `(string: "")` - Provides a name to the specified issuer. The
  name must be unique across all issuers and not be the reserved value
  `default`. When no value is supplied and the path is `/pki/root/rotate/:type`,
  the default value of `"next"` will be used.

- `key_name` `(string: "")` - When a new key is created with this request,
  optionally specifies the name for this. The global ref `default` may not
  be used as a name.

- `key_ref` `(string: "default")` - Specifies the key (either `default`, by
  name, or by identifier) to use for generating this request. Only suitable
  for `type=existing` requests.

- `common_name` `(string: "example.com")` - Specifies the requested CN for the
  certificate. If more than one `common_name` is desired, specify the
  alternative names in the `alt_names` list.

- `alt_names` `(string: "")` - Specifies the requested Subject Alternative
  Names, in a comma-delimited list. These can be host names or email addresses;
  they will be parsed into their respective fields.

- `ip_sans` `(string: "")` - Specifies the requested IP Subject Alternative
  Names, in a comma-delimited list.

- `uri_sans` `(string: "")` - Specifies the requested URI Subject Alternative
  Names, in a comma-delimited list.

- `other_sans` `(string: "")` - Specifies custom OID/UTF8-string SANs. These
  must match values specified on the role in `allowed_other_sans` (see role
  creation for allowed_other_sans globbing rules).
  The format is the same as OpenSSL: `<oid>;<type>:<value>` where the
  only current valid type is `UTF8`. This can be a comma-delimited list or a
  JSON string slice.

- `ttl` `(string: "")` - Specifies the requested Time To Live (after which the
  certificate will be expired). This cannot be larger than the engine's max (or,
  if not set, the system max). See `not_after` as an alternative for setting an
  absolute end date (rather than a relative one).

- `format` `(string: "pem")` - Specifies the format for returned data. Can be
  `pem`, `der`, or `pem_bundle`. If `der`, the output is base64 encoded. If
  `pem_bundle`, the `certificate` field will contain the private key (if
  exported) and certificate, concatenated; if the issuing CA is not a
  Vault-derived self-signed root, this will be included as well.

- `private_key_format` `(string: "der")` - Specifies the format for marshaling
  the private key within the private_key response field. Defaults to `der` which will
  return either base64-encoded DER or PEM-encoded DER, depending on the value of
  `format`. The other option is `pkcs8` which will return the key marshalled as
  PEM-encoded PKCS8.

~> **Note** that this does not apply to the private key within the certificate
  field if `format=pem_bundle` parameter is specified.

- `key_type` `(string: "rsa")` - Specifies the desired key type; must be `rsa`, `ed25519`
  or `ec`.

~> **Note**: In FIPS 140-2 mode, the following algorithms are not certified
   and thus should not be used: `ed25519`.

- `key_bits` `(int: 0)` - Specifies the number of bits to use for the
  generated keys. Allowed values are 0 (universal default); with
  `key_type=rsa`, allowed values are: 2048 (default), 3072, or
  4096; with `key_type=ec`, allowed values are: 224, 256 (default),
  384, or 521; ignored with `key_type=ed25519`.

- `max_path_length` `(int: -1)` - Specifies the maximum path length to encode in
  the generated certificate. `-1` means no limit. Unless the signing certificate
  has a maximum path length set, in which case the path length is set to one
  less than that of the signing certificate. A limit of `0` means a literal
  path length of zero.

- `exclude_cn_from_sans` `(bool: false)` - If true, the given `common_name` will
  not be included in DNS or Email Subject Alternate Names (as appropriate).
  Useful if the CN is not a hostname or email address, but is instead some
  human-readable identifier.

- `permitted_dns_domains` `(string: "")` - A comma separated string (or, string
  array) containing DNS domains for which certificates are allowed to be issued
  or signed by this CA certificate. Note that subdomains are allowed, as per
  [RFC 5280 Section 4.2.1.10 - Name
  Constraints](https://tools.ietf.org/html/rfc5280#section-4.2.1.10).

- `ou` `(string: "")` - Specifies the OU (OrganizationalUnit) values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `organization` `(string: "")` - Specifies the O (Organization) values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `country` `(string: "")` - Specifies the C (Country) values in the subject
  field of the resulting certificate. This is a comma-separated string or JSON
  array.

- `locality` `(string: "")` - Specifies the L (Locality) values in the subject
  field of the resulting certificate. This is a comma-separated string or JSON
  array.

- `province` `(string: "")` - Specifies the ST (Province) values in the subject
  field of the resulting certificate. This is a comma-separated string or JSON
  array.

- `street_address` `(string: "")` - Specifies the Street Address values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `postal_code` `(string: "")` - Specifies the Postal Code values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `serial_number` `(string: "")` -  - Specifies the default Subject's named
  [Serial Number](https://datatracker.ietf.org/doc/html/rfc4519#section-2.31)
  value, if any. If you want more than one, specify alternative names in the
  `alt_names` map using OID 2.5.4.5. Note that this has no impact on the
  Certificate's serial number field, which Vault randomly generates.

- `not_before_duration` `(duration: "30s")` - Specifies the duration by which to
  backdate the NotBefore property. This value has no impact in the validity period
  of the requested certificate, specified in the `ttl` field.
  Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).

- `not_after` `(string)` - Set the Not After field of the certificate with
  specified date value. The value format should be given in UTC format
  `YYYY-MM-ddTHH:MM:SSZ`. Supports the Y10K end date for IEEE 802.1AR-2018
  standard devices, `9999-12-31T23:59:59Z`.

- ~> Note: Keys of type `rsa` currently only support PKCS#1 v1.5 signatures.

#### Managed Keys Parameters

See [Managed Keys](https://developer.hashicorp.com/vault/api-docs/secret/pki#managed-keys) for additional details on this feature, if
`type` was set to `kms`. One of the following parameters must be set

- `managed_key_name` `(string: "")` - The managed key's configured name.

- `managed_key_id` `(string: "")` - The managed key's UUID.

### Intermediate CSR Config `intermediate_csr`

- `type` `(string: "internal")` - Specifies the type of the intermediate to
  create. If `exported`, the private key will be returned in the response; if
  `internal` the private key will not be returned and _cannot be retrieved
  later_; if `existing`, we expect the `key_ref` parameter to use existing
  key material to create the CSR; `kms` is also supported: [see managed keys](https://developer.hashicorp.com/vault/api-docs/secret/pki#managed-keys) for additional details. This parameter is part of the request URL.

- `common_name` `(string: "example.com Intermediate Authority")` - Specifies the requested CN for the
  certificate. If more than one `common_name` is desired, specify the
  alternative names in the `alt_names` list.

- `alt_names` `(string: "")` - Specifies the requested Subject Alternative
  Names, in a comma-delimited list. These can be host names or email addresses;
  they will be parsed into their respective fields.

- `ip_sans` `(string: "")` - Specifies the requested IP Subject Alternative
  Names, in a comma-delimited list.

- `uri_sans` `(string: "")` - Specifies the requested URI Subject Alternative
  Names, in a comma-delimited list.

- `other_sans` `(string: "")` - Specifies custom OID/UTF8-string SANs. These
  must match values specified on the role in `allowed_other_sans` (see role
  creation for allowed_other_sans globbing rules).
  The format is the same as OpenSSL: `<oid>;<type>:<value>` where the
  only current valid type is `UTF8`. This can be a comma-delimited list or a
  JSON string slice.

- `format` `(string: "pem")` - Specifies the format for returned data. This can be
  `pem`, `der`, or `pem_bundle`; defaults to `pem`. If `der`, the output is
  base64 encoded. If `pem_bundle`, the `csr` field will contain the private key
  (if exported) and CSR, concatenated.

- `private_key_format` `(string: "der")` - Specifies the format for marshaling
  the private key within the private_key response field. Defaults to `der` which will
  return either base64-encoded DER or PEM-encoded DER, depending on the value of
  `format`. The other option is `pkcs8` which will return the key marshalled as
  PEM-encoded PKCS8.

~> **Note** that this does not apply to the private key within the certificate
  field if `format=pem_bundle` parameter is specified.

- `key_type` `(string: "rsa")` - Specifies the desired key type; must be `rsa`, `ed25519`
  or `ec`. Not suitable for `type=existing` requests.

~> **Note**: In FIPS 140-2 mode, the following algorithms are not certified
   and thus should not be used: `ed25519`.

~> **Note**: Keys of type `rsa` currently only support PKCS#1 v1.5 signatures.
   This includes any managed keys.

- `key_bits` `(int: 0)` - Specifies the number of bits to use for the
  generated keys. Allowed values are 0 (universal default); with
  `key_type=rsa`, allowed values are: 2048 (default), 3072, or
  4096; with `key_type=ec`, allowed values are: 224, 256 (default),
  384, or 521; ignored with `key_type=ed25519`. Not suitable for
  `type=existing` requests.

- `key_name` `(string: "")` - When a new key is created with this request,
  optionally specifies the name for this. The global ref `default` may not
  be used as a name.

- `key_ref` `(string: "default")` - Specifies the key (either `default`, by
  name, or by identifier) to use for generating this request. Only suitable
  for `type=existing` requests.

- `signature_bits` `(int: 0)` - Specifies the number of bits to use in
  the signature algorithm; accepts 256 for SHA-2-256, 384 for SHA-2-384,
  and 512 for SHA-2-512. Defaults to 0 to automatically detect based
  on issuer's key length (SHA-2-256 for RSA keys, and matching the curve size
  for NIST P-Curves).

~> **Note**: ECDSA and Ed25519 issuers do not follow configuration of the
`signature_bits` value; only RSA issuers will change signature types
based on this parameter.

- `exclude_cn_from_sans` `(bool: false)` - If true, the given `common_name` will
  not be included in DNS or Email Subject Alternate Names (as appropriate).
  Useful if the CN is not a hostname or email address, but is instead some
  human-readable identifier.

- `ou` `(string: "")` - Specifies the OU (OrganizationalUnit) values in the
  subject field of the resulting CSR. This is a comma-separated string
  or JSON array.

- `organization` `(string: "")` - Specifies the O (Organization) values in the
  subject field of the resulting CSR. This is a comma-separated string
  or JSON array.

- `country` `(string: "")` - Specifies the C (Country) values in the subject
  field of the resulting CSR. This is a comma-separated string or JSON
  array.

- `locality` `(string: "")` - Specifies the L (Locality) values in the subject
  field of the resulting CSR. This is a comma-separated string or JSON
  array.

- `province` `(string: "")` - Specifies the ST (Province) values in the subject
  field of the resulting CSR. This is a comma-separated string or JSON
  array.

- `street_address` `(string: "")` - Specifies the Street Address values in the
  subject field of the resulting CSR. This is a comma-separated string
  or JSON array.

- `postal_code` `(string: "")` - Specifies the Postal Code values in the
  subject field of the resulting CSR. This is a comma-separated string
  or JSON array.

- `serial_number` `(string: "")` - Specifies the requested Subject's named
  [Serial Number](https://datatracker.ietf.org/doc/html/rfc4519#section-2.31)
  value, if any. If you want more than one, specify alternative names in the
  `alt_names` map using OID 2.5.4.5. Note that this has no impact on the
  Certificate's serial number field, which Vault randomly generates.

- `add_basic_constraints` `(bool: false)` - Whether to add a Basic Constraints
  extension with CA: true. Only needed as a workaround in some compatibility
  scenarios with Active Directory Certificate Services.

#### Managed Keys Parameters

See [Managed Keys](https://developer.hashicorp.com/vault/api-docs/secret/pki#managed-keys) for additional details on this feature, if
`type` was set to `kms`. One of the following parameters must be set

- `managed_key_name` `(string: "")` - The managed key's configured name.

- `managed_key_id` `(string: "")` - The managed key's UUID.

### Intermediate CA Config `intermediate_ca`

- `csr` `(string: <auto_generated>)` - Specifies the PEM-encoded CSR to be signed.

- `common_name` `(string: "")` - Specifies the requested CN for the
  certificate. If more than one `common_name` is desired, specify the
  alternative names in the `alt_names` list.

- `alt_names` `(string: "")` - Specifies the requested Subject Alternative
  Names, in a comma-delimited list. These can be host names or email addresses;
  they will be parsed into their respective fields.

- `ip_sans` `(string: "")` - Specifies the requested IP Subject Alternative
  Names, in a comma-delimited list.

- `uri_sans` `(string: "")` - Specifies the requested URI Subject Alternative
  Names, in a comma-delimited list.

- `other_sans` `(string: "")` - Specifies custom OID/UTF8-string SANs. These
  must match values specified on the role in `allowed_other_sans` (see role
  creation for allowed_other_sans globbing rules).
  The format is the same as OpenSSL: `<oid>;<type>:<value>` where the
  only current valid type is `UTF8`. This can be a comma-delimited list or a
  JSON string slice.

- `ttl` `(string: "")` - Specifies the requested Time To Live (after which the
  certificate will be expired). This cannot be larger than the engine's max (or,
  if not set, the system max). However, this can be after the expiration of the
  signing CA. See `not_after` as an alternative for setting an absolute end date
  (rather than a relative one).

- `format` `(string: "pem_bundle")` - Specifies the format for returned data. Can be
  `pem`, `der`, or `pem_bundle`. If `der`, the output is base64 encoded. If
  `pem_bundle`, the `certificate` field will contain the certificate and, if the
  issuing CA is not a Vault-derived self-signed root, it will be concatenated
  with the certificate.

- `max_path_length` `(int: -1)` - Specifies the maximum path length to encode in
  the generated certificate. `-1`, means no limit, unless the signing
  certificate has a maximum path length set, in which case the path length is
  set to one less than that of the signing certificate. A limit of `0` means a
  literal path length of zero.

- `exclude_cn_from_sans` `(bool: false)` - If true, the given `common_name` will
  not be included in DNS or Email Subject Alternate Names (as appropriate).
  Useful if the CN is not a hostname or email address, but is instead some
  human-readable identifier.

- `use_csr_values` `(bool: false)` - If set to `true`, then: 1) Subject
  information, including names and alternate names, will be preserved from the
  CSR rather than using the values provided in the other parameters to this
  path; 2) Any key usages (for instance, non-repudiation) requested in the CSR
  will be added to the basic set of key usages used for CA certs signed by this
  path; 3) Extensions requested in the CSR will be copied into the issued
  certificate.

- `permitted_dns_domains` `(string: "")` - A comma separated string (or, string
  array) containing DNS domains for which certificates are allowed to be issued
  or signed by this CA certificate. Supports subdomains via a `.` in front of
  the domain, as per [RFC 5280 Section 4.2.1.10 - Name
  Constraints](https://tools.ietf.org/html/rfc5280#section-4.2.1.10)

- `ou` `(string: "")` - Specifies the OU (OrganizationalUnit) values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `organization` `(string: "")` - Specifies the O (Organization) values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `country` `(string: "")` - Specifies the C (Country) values in the subject
  field of the resulting certificate. This is a comma-separated string or JSON
  array.

- `locality` `(string: "")` - Specifies the L (Locality) values in the subject
  field of the resulting certificate. This is a comma-separated string or JSON
  array.

- `province` `(string: "")` - Specifies the ST (Province) values in the subject
  field of the resulting certificate. This is a comma-separated string or JSON
  array.

- `street_address` `(string: "")` - Specifies the Street Address values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `postal_code` `(string: "")` - Specifies the Postal Code values in the
  subject field of the resulting certificate. This is a comma-separated string
  or JSON array.

- `serial_number` `(string: "")` -  - Specifies the requested Subject's named
  [Serial Number](https://datatracker.ietf.org/doc/html/rfc4519#section-2.31)
  value, if any. If you want more than one, specify alternative names in the
  `alt_names` map using OID 2.5.4.5. Note that this has no impact on the
  Certificate's serial number field, which Vault randomly generates.

- `not_before_duration` `(duration: "30s")` - Specifies the duration by which to
  backdate the NotBefore property. This value has no impact in the validity period
  of the requested certificate, specified in the `ttl` field.
  Uses [duration format strings](https://developer.hashicorp.com/vault/docs/concepts/duration-format).

- `not_after` `(string)` - Set the Not After field of the certificate with
  specified date value. The value format should be given in UTC format
  `YYYY-MM-ddTHH:MM:SSZ`. Supports the Y10K end date for IEEE 802.1AR-2018
  standard devices, `9999-12-31T23:59:59Z`.

- `signature_bits` `(int: 0)` - Specifies the number of bits to use in
  the signature algorithm; accepts 256 for SHA-2-256, 384 for SHA-2-384,
  and 512 for SHA-2-512. Defaults to 0 to automatically detect based
  on issuer's key length (SHA-2-256 for RSA keys, and matching the curve size
  for NIST P-Curves).

~> **Note**: ECDSA and Ed25519 issuers do not follow configuration of the
   `signature_bits` value; only RSA issuers will change signature types
   based on this parameter.

- `skid` `(string: "")` - Value for the Subject Key Identifier field
  (RFC 5280 Section 4.2.1.2). Specified as a string in hex format. Default
  is empty, allowing Vault to automatically calculate the SKID according
  to method one in the above RFC section.

~> **Note**: This value should ONLY be used when cross-signing to mimic
   the existing certificate's SKID value; this is necessary to allow
   certain TLS implementations (such as OpenSSL) which use SKID/AKID
   matches in chain building to restrict possible valid chains.

- `use_pss` `(bool: false)` - Specifies whether or not to use PSS signatures
  over PKCS#1v1.5 signatures when a RSA-type issuer is used. Ignored for
  ECDSA/Ed25519 issuers.

### Role Config `role`

- `name` `(string: "benchmark-sign")` - Specifies the name of the role to create. This
  is part of the request URL.

- `issuer_ref`: `(string: "default")` - Specifies the default issuer of this
  request. May be the value `default`, a name, or an issuer ID. Use ACLs to
  prevent access to the `/pki/issuer/:issuer_ref/{issue,sign}/:name` paths
  to prevent users overriding the role's `issuer_ref` value.

~> Note: This parameter is stored as-is; if the reference is to a name, it
   is **not** resolve to an identifier. Deletion of issuers (or updating their
   names) **may** result in issuance failing or using an unexpected issuer.

~> **Note**: existing roles from previous Vault versions are migrated to use
   the `issuer_ref=default`.

- `ttl` `(string: "5m")` - Specifies the Time To Live value to be used for the
  validity period of the requested certificate, provided as a string duration
  with time suffix. Hour is the largest suffix. The value specified is strictly
  used for future validity. If not set, uses the system default value or the
  value of `max_ttl`, whichever is shorter. See `not_after` as an alternative
  for setting an absolute end date (rather than a relative one).

- `max_ttl` `(string: "")` - Specifies the maximum Time To Live provided as a
  string duration with time suffix. Hour is the largest suffix. If not set,
  defaults to the system maximum lease TTL.

- `allow_localhost` `(bool: true)` - Specifies if clients can request
  certificates for `localhost` as one of the requested common names. This is
  useful for testing and to allow clients on a single host to talk securely.

~> **Note**: This strictly applies to `localhost` and `localdomain` when this
   option is enabled. Additionally, even if this option is disabled, if either
   name is included in `allowed_domains`, the match rules for that option
   could permit issuance of a certificate for `localhost`.

- `allowed_domains` `(list: [])` - Specifies the domains this role is allowed
  to issue certificates for. This is used with the `allow_bare_domains`,
  `allow_subdomains`, and `allow_glob_domains` options to determine the type
  of matching between these domains and the values of common name, DNS-typed
  SAN entries, and Email-typed SAN entries. When `allow_any_name` is used,
  this attribute has no effect.

~> **Note**: The three options `allow_bare_domains`, `allow_subdomains`, and
   `allow_glob_domains` are each independent of each other. That is, at least
   one type of allowed matching must describe the relationship between the
   `allowed_domains` list and the names on the issued certificate. For example,
   given `allowed_domain=foo.*.example.com` and `allow_subdomains=true` and
   `allow_glob_domains=true`, a request for `bar.foo.baz.example.com` won't
   be permitted, even though it `foo.baz.example.com` matches the glob
   `foo.*.example.com` and `bar` is a subdomain of that.

- `allowed_domains_template` `(bool: false)` - When set, `allowed_domains`
  may contain templates, as with [ACL Path Templating](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies).
  Non-templated domains are also still permitted.

- `allow_bare_domains` `(bool: false)` - Specifies if clients can request
  certificates matching the value of the actual domains themselves; e.g. if a
  configured domain set with `allowed_domains` is `example.com`, this allows
  clients to actually request a certificate containing the name `example.com` as
  one of the DNS values on the final certificate. In some scenarios, this can be
  considered a security risk. Note that when an `allowed_domain` field contains
  a potential wildcard character (for example, `allowed_domains=*.example.com`)
  and `allow_bare_domains` and `allow_wildcard_certificates` are both enabled,
  issuance of a wildcard certificate for `*.example.com` will be permitted.

- `allow_subdomains` `(bool: true)` - Specifies if clients can request
  certificates with CNs that are subdomains of the CNs allowed by the other role
  options. _This includes wildcard subdomains._ For example, an
  `allowed_domains` value of `example.com` with this option set to true will
  allow `foo.example.com` and `bar.example.com` as well as `*.example.com`. To
  restrict issuance of wildcards by this option, see `allow_wildcard_certificates`
  below. This option is redundant when using the `allow_any_name` option.

- `allow_glob_domains` `(bool: false)` - Allows names specified in
  `allowed_domains` to contain glob patterns (e.g. `ftp*.example.com`). Clients
  will be allowed to request certificates with names matching the glob
  patterns.

~> **Note**: These globs behave like shell-style globs and can match
  across multiple domain parts. For example, `allowed_domains=*.example.com`
  with `allow_glob_domains` enabled will match not only `foo.example.com` but
  also `baz.bar.foo.example.com`.

~> **Warning**: Glob patterns will match wildcard domains and permit their
   issuance unless otherwise restricted by `allow_wildcard_certificates`. For
   instance, with `allowed_domains=*.*.example.com` and both `allow_glob_domains`
   and `allow_wildcard_certificates` enabled, we will permit the issuance of
   a wildcard certificate for `*.foo.example.com`.

- `allow_wildcard_certificates` `(bool: true)` - Allows the issuance of
  certificates with [RFC 6125](https://tools.ietf.org/html/rfc6125) wildcards
  in the CN field. When set to `false`, this prevents wildcards from being
  issued even if they would've been allowed by an option above. We support
  the following four wildcard types:

  - `*.example.com`, a single wildcard as the entire left-most label,
  - `foo*.example.com`, a single suffixed wildcard in the left-most label,
  - `*foo.example.com`, a single prefixed wildcard in the left-most label, and
  - `f*o.example.com`, a single interior wildcard in the left-most label.

- `allow_any_name` `(bool: true)` - Specifies if clients can request any CN.
  Useful in some circumstances, but make sure you understand whether it is
  appropriate for your installation before enabling it. Note that both
  `enforce_hostnames` and `allow_wildcard_certificates` are still checked,
  which may introduce limitations on issuance with this option.

- `enforce_hostnames` `(bool: true)` - Specifies if only valid host names are
  allowed for CNs, DNS SANs, and the host part of email addresses.

- `allow_ip_sans` `(bool: true)` - Specifies if clients can request IP Subject
  Alternative Names. No authorization checking is performed except to verify
  that the given values are valid IP addresses.

- `allowed_uri_sans` `(string: "")` - Defines allowed URI Subject
  Alternative Names. No authorization checking is performed except to verify
  that the given values are valid URIs. This can be a comma-delimited list or
  a JSON string slice. Values can contain glob patterns (e.g.
  `spiffe://hostname/*`).

- `allowed_uri_sans_template` `(bool: false)` - When set, `allowed_uri_sans`
  may contain templates, as with [ACL Path Templating](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies).
  Non-templated domains are also still permitted.

- `allowed_other_sans` `(string: "")` - Defines allowed custom OID/UTF8-string
  SANs. This can be a comma-delimited list or a JSON string slice, where
  each element has the same format as OpenSSL: `<oid>;<type>:<value>`, but
  the only valid type is `UTF8` or `UTF-8`. The `value` part of an element
  may be a `*` to allow any value with that OID.
  Alternatively, specifying a single `*` will allow any `other_sans` input.

- `allowed_serial_numbers` `(string: "")` - If set, an array of allowed serial
  numbers to be requested during certificate issuance. These values support
  shell-style globbing. When empty, custom-specified serial numbers will be
  forbidden. It is strongly recommended to allow Vault to generate random
  serial numbers instead.

- `server_flag` `(bool: true)` - Specifies if certificates are flagged for
  server authentication use. See [RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
  for information about the Extended Key Usage field.

- `client_flag` `(bool: true)` - Specifies if certificates are flagged for
  client authentication use. See [RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
  for information about the Extended Key Usage field.

- `code_signing_flag` `(bool: false)` - Specifies if certificates are flagged
  for code signing use. See [RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
  for information about the Extended Key Usage field.

- `email_protection_flag` `(bool: false)` - Specifies if certificates are
  flagged for email protection use. See [RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
  for information about the Extended Key Usage field.

- `key_type` `(string: "rsa")` - Specifies the type of key to generate for
  generated private keys and the type of key expected for submitted CSRs.
  Currently, `rsa`, `ec`, and `ed25519` are supported, or when signing
  existing CSRs, `any` can be specified to allow keys of either type
  and with any bit size (subject to >=2048 bits for RSA keys or >= 224 for EC keys).
  When `any` is used, this role cannot generate certificates and can only
  be used to sign CSRs.

~> **Note**: In FIPS 140-2 mode, the following algorithms are not certified
   and thus should not be used: `ed25519`.

- `key_bits` `(int: 0)` - Specifies the number of bits to use for the
  generated keys. Allowed values are 0 (universal default); with
  `key_type=rsa`, allowed values are: 2048 (default), 3072, or
  4096; with `key_type=ec`, allowed values are: 224, 256 (default),
  384, or 521; ignored with `key_type=ed25519` or in signing operations
  when `key_type=any`.

- `signature_bits` `(int: 0)` - Specifies the number of bits to use in
  the signature algorithm; accepts 256 for SHA-2-256, 384 for SHA-2-384,
  and 512 for SHA-2-512. Defaults to 0 to automatically detect based
  on issuer's key length (SHA-2-256 for RSA keys, and matching the curve size
  for NIST P-Curves).

~> **Note**: ECDSA and Ed25519 issuers do not follow configuration of the
   `signature_bits` value; only RSA issuers will change signature types
   based on this parameter.

- `use_pss` `(bool: false)` - Specifies whether or not to use PSS signatures
  over PKCS#1v1.5 signatures when a RSA-type issuer is used. Ignored for
  ECDSA/Ed25519 issuers.

- `key_usage` `(list: ["DigitalSignature", "KeyAgreement", "KeyEncipherment"])` -
  Specifies the allowed key usage constraint on issued certificates. Valid
  values can be found at <https://golang.org/pkg/crypto/x509/#KeyUsage> - simply
  drop the `KeyUsage` part of the value. Values are not case-sensitive. To
  specify no key usage constraints, set this to an empty list. See
  [RFC 5280 Section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)
  for more information about the Key Usage field.

- `ext_key_usage` `(list: [])` -
  Specifies the allowed extended key usage constraint on issued certificates. Valid
  values can be found at <https://golang.org/pkg/crypto/x509/#ExtKeyUsage> - simply
  drop the `ExtKeyUsage` part of the value. Values are not case-sensitive. To
  specify no key usage constraints, set this to an empty list. See
  [RFC 5280 Section 4.2.1.12](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12)
  for information about the Extended Key Usage field.

- `ext_key_usage_oids` `(string: "")` - A comma-separated string or list of extended
  key usage oids. Useful for adding EKUs not supported by the Go standard library.

- `use_csr_common_name` `(bool: true)` - When used with the CSR signing
  endpoint, the common name in the CSR will be used instead of taken from the
  JSON data. This does not include any requested SANs in the CSR; use
  `use_csr_sans` for that.

- `use_csr_sans` `(bool: true)` - When used with the CSR signing endpoint, the
  subject alternate names in the CSR will be used instead of taken from the JSON
  data. This does not include the common name in the CSR; use
  `use_csr_common_name` for that.

- `ou` `(string: "")` - Specifies the OU (OrganizationalUnit) values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `organization` `(string: "")` - Specifies the O (Organization) values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `country` `(string: "")` - Specifies the C (Country) values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `locality` `(string: "")` - Specifies the L (Locality) values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `province` `(string: "")` - Specifies the ST (Province) values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `street_address` `(string: "")` - Specifies the Street Address values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `postal_code` `(string: "")` - Specifies the Postal Code values in the
  subject field of issued certificates. This is a comma-separated string or
  JSON array.

- `generate_lease` `(bool: false)` - Specifies if certificates issued/signed
  against this role will have Vault leases attached to them. Certificates can be
  added to the CRL by `vault revoke <lease_id>` when certificates are associated
  with leases. It can also be done using the `pki/revoke` endpoint. However,
  when lease generation is disabled, invoking `pki/revoke` would be the only way
  to add the certificates to the CRL. When large number of certificates are
  generated with long lifetimes, it is recommended that lease generation be
  disabled, as large amount of leases adversely affect the startup time of Vault.

- `no_store` `(bool: false)` - If set, certificates issued/signed against this
  role will not be stored in the storage backend. This can improve performance
  when issuing large numbers of certificates. However, certificates issued in
  this way cannot be enumerated or revoked, so this option is recommended only
  for certificates that are non-sensitive, or extremely short-lived. This
  option implies a value of `false` for `generate_lease`.

- `require_cn` `(bool: true)` - If set to false, makes the `common_name` field
  optional while generating a certificate.

- `policy_identifiers` `(list: [])` - A comma-separated string or list of policy
  OIDs.

- `basic_constraints_valid_for_non_ca` `(bool: false)` - Mark Basic Constraints
  valid when issuing non-CA certificates.

- `not_before_duration` `(duration: "30s")` - Specifies the duration by which to
  backdate the NotBefore property. This value has no impact in the validity period
  of the requested certificate, specified in the `ttl` field.

- `not_after` `(string)` - Set the Not After field of the certificate with
  specified date value. The value format should be given in UTC format
  `YYYY-MM-ddTHH:MM:SSZ`. Supports the Y10K end date for IEEE 802.1AR-2018
  standard devices, `9999-12-31T23:59:59Z`.

- `cn_validations` `(list: ["email", "hostname"])` - Validations to run on the
  Common Name field of the certificate. Valid values include:

  - `email`, to ensure the Common Name is an email address (contains an `@` sign),
  - `hostname`, to ensure the Common Name is a hostname (otherwise).

  Multiple values can be separated with a comma or specified as a list and use
  OR semantics (either email or hostname in the CN are allowed). When the
  special value "disabled" is used (must be specified alone), none of the usual
  validation is run (including but not limited to `allowed_domains` and basic
  correctness validation around email addresses and domain names). This allows
  non-standard CNs to be used verbatim from the request.

- `allowed_user_ids` `(string: "")` - Comma separated, globbing list of User ID
  Subject components to allow on requests. By default, no user IDs are allowed.
  Use the bare wildcard `*` value to allow any value. See also the `user_ids`
  request parameter.

### Sign Config `sign`

- `name` `(string: "benchmark-sign)` - Specifies the name of the role to create the
  certificate against. This is part of the request URL.

- `csr` `(string: <auto_generated>)` - Specifies the PEM-encoded CSR, or file location
  to the PEM-encoded CSR. If not provided, vault-benchmark will auto generate one with
  the following parameters:

  ```go
    {
      common_name:         "test.vault.benchmark",
      country:             ["US"],
      organization:        ["Hashicorp"],
      locality:            ["San Francisco"],
      organizational_unit: ["VaultBenchmarking"],
      key_type:            "rsa",
      key_bits:            2048,
      not_after:           <current_time + 1 hour>
    }
  ```

- `common_name` `(string: <required>)` - Specifies the requested CN for the
  certificate. If the CN is allowed by role policy, it will be issued. If
  more than one `common_name` is desired, specify the alternative names in
  the `alt_names` list.

- `alt_names` `(string: "")` - Specifies the requested Subject Alternative
  Names, in a comma-delimited list. These can be host names or email addresses;
  they will be parsed into their respective fields. If any requested names do
  not match role policy, the entire request will be denied.

- `other_sans` `(string: "")` - Specifies custom OID/UTF8-string SANs. These
  must match values specified on the role in `allowed_other_sans` (see role
  creation for allowed_other_sans globbing rules).
  The format is the same as OpenSSL: `<oid>;<type>:<value>` where the
  only current valid type is `UTF8`. This can be a comma-delimited list or a
  JSON string slice.

- `ip_sans` `(string: "")` - Specifies the requested IP Subject Alternative
  Names, in a comma-delimited list. Only valid if the role allows IP SANs (which
  is the default).

- `uri_sans` `(string: "")` - Specifies the requested URI Subject Alternative
  Names, in a comma-delimited list. If any requested URIs do not match role policy,
  the entire request will be denied.

- `ttl` `(string: "")` - Specifies the requested Time To Live. Cannot be greater
  than the role's `max_ttl` value. If not provided, the role's `ttl` value will
  be used. Note that the role values default to system values if not explicitly
  set. See `not_after` as an alternative for setting an absolute end date
  (rather than a relative one).

- `format` `(string: "pem")` - Specifies the format for returned data. Can be
  `pem`, `der`, or `pem_bundle`. If `der`, the output is base64 encoded. If
  `pem_bundle`, the `certificate` field will contain the certificate and, if the
  issuing CA is not a Vault-derived self-signed root, it will be concatenated
  with the certificate.

- `exclude_cn_from_sans` `(bool: false)` - If true, the given `common_name` will
  not be included in DNS or Email Subject Alternate Names (as appropriate).
  Useful if the CN is not a hostname or email address, but is instead some
  human-readable identifier.

- `not_after` `(string)` - Set the Not After field of the certificate with
  specified date value. The value format should be given in UTC format
  `YYYY-MM-ddTHH:MM:SSZ`. Supports the Y10K end date for IEEE 802.1AR-2018
  standard devices, `9999-12-31T23:59:59Z`.

- `remove_roots_from_chain` `(bool: false)` - If true, the returned `ca_chain`
  field will not include any self-signed CA certificates. Useful if end-users
  already have the root CA in their trust store.

- `user_ids` `(string: "")` - Specifies the comma-separated list of requested
  User ID (OID 0.9.2342.19200300.100.1.1) Subject values to be placed on the
  signed certificate. This field is validated against `allowed_user_ids` on
  the role.

Additional configuration examples can be found in the [pki configuration directory](/example-configs/pki/).
