# Transit Secret Configuration Options

This benchmark tests the performance of the transit operations.

## Test Parameters

### General Transit Config

- `payload_len` _(int: 128)_: Specifies the payload length to use for encryption/decryption operations.
- `context_len` _(int: 32)_: Specifies the context length to use for encryption/decryption operations.

### Key Config `keys`

- `name` _(string: "test")_ – Specifies the name of the encryption key to create. This is specified as part of the URL.
- `convergent_encryption` _(bool: false)_: If enabled, the key will support convergent encryption, where the same plaintext creates the same ciphertext. This requires derived to be set to true. When enabled, each encryption(/decryption/rewrap/datakey) operation will derive a nonce value rather than randomly generate it.
- `derived` _(bool: false)_: Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this named key must provide a context which is used for key derivation.
- `exportable` _(bool: false)_ - Enables keys to be exportable. This allows for all the valid keys in the key ring to be exported. Once set, this cannot be disabled.
- `allow_plaintext_backup` _(bool: false)_ - If set, enables taking backup of named key in the plaintext format. Once set, this cannot be disabled.
- `type` _(string: "rsa-2048")_: Specifies the type of key to create.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#type) for supported values.
- `key_size` _(int: "0")_ - The key size in bytes for algorithms
  that allow variable key sizes.  Currently only applicable to HMAC, where
  it must be between 32 and 512 bytes.
- `auto_rotate_period` _(duration: "0")_ – The period at which
  this key should be rotated automatically. Setting this to "0" (the default)
  will disable automatic key rotation. This value cannot be shorter than one
  hour. Uses [duration format strings](/vault/docs/concepts/duration-format).
- `managed_key_name` _(string: "")_ - The name of the managed key to use for this transit key.
- `managed_key_id` _(string: "")_ - The UUID of the managed key to use for this transit key.

### Sign Config `sign`

- `name` _(string: "test")_ – Specifies the name of the encryption key to
  use for signing. This is specified as part of the URL.
- `key_version` _(int: 0)_ – Specifies the version of the key to use for
  signing. If not set, uses the latest version. Must be greater than or equal
  to the key's `min_encryption_version`, if set.
- `hash_algorithm` _(string: "sha2-256")_:  Specifies the hash algorithm to use for supporting key types (notably, not including ed25519 which specifies its own hash algorithm).  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#hash_algorithm) for supported values.
- `input` _(string: "")_ – Specifies the **base64 encoded** input data. One of
  `input` or `batch_input` must be supplied.
- `reference` _(string: "")_ -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using ‘batch_input’ below.
- `batch_input` _([]interface{}: nil)_ – Specifies a list of items for processing.
  When this parameter is set, any supplied 'input' or 'context' parameters will be
  ignored. Responses are returned in the 'batch_results' array component of the
  'data' element of the response. Any batch output will preserve the order of the
  batch input. If the input data value of an item is invalid, the
  corresponding item in the 'batch_results' will have the key 'error' with a value
  describing the error.
- `context` _(string: "")_ - Base64 encoded context for key derivation.
  Required if key derivation is enabled; currently only available with ed25519
  keys.
- `prehashed` _(bool: false)_ - Set to `true` when the input is already hashed.
  If the key type is `rsa-2048`, `rsa-3072` or `rsa-4096`, then the algorithm used to hash
  the input should be indicated by the `hash_algorithm` parameter. Just as the
  value to sign should be the base64-encoded representation of the exact binary
  data you want signed, when set, `input` is expected to be base64-encoded
  binary hashed data, not hex-formatted. (As an example, on the command line,
  you could generate a suitable input via `openssl dgst -sha256 -binary | base64`.)
- `signature_algorithm` _(string: "pss")_: When using a RSA key, specifies the RSA signature algorithm to use for signing.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#signature_algorithm) for supported values.
- `marshaling_algorithm` _(string: "asn1")_: Specifies the way in which the signature should be marshaled. This currently only applies to ECDSA keys.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#marshaling_algorithm) for supported values.
- `salt_length` _(string: "auto")_ – The salt length used to sign. This currently only applies to the RSA PSS signature scheme.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#salt_length) for supported values.

### Verify Config `verify`

- `name` _(string: test)_ – Specifies the name of the encryption key that
  was used to generate the signature or HMAC.
- `hash_algorithm` _(string: "sha2-256")_ – Specifies the hash algorithm to use. This
  can also be specified as part of the URL.
- `input` _(string: "")_ – Specifies the **base64 encoded** input data. One of
  `input` or `batch_input` must be supplied.
- `signature` _(string: "")_ – Specifies the signature output from the
  `/transit/sign` function. Either this must be supplied or `hmac` must be
  supplied.
- `hmac` _(string: "")_ – Specifies the signature output from the
  `/transit/hmac` function. Either this must be supplied or `signature` must be
  supplied.
- `reference` _(string: "")_ -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using ‘batch_input’ below.
- `batch_input` _([]interface{}: nil)_ – Specifies a list of items for processing.
  When this parameter is set, any supplied 'input', 'hmac' or 'signature' parameters
  will be ignored. 'batch_input' items should contain an 'input' parameter and
  either an 'hmac' or 'signature' parameter. All items in the batch must consistently
  supply either 'hmac' or 'signature' parameters. It is an error for some items to
  supply 'hmac' while others supply 'signature'. Responses are returned in the
  'batch_results' array component of the 'data' element of the response. Any batch
  output will preserve the order of the batch input. If the input data value of an
  item is invalid, the corresponding item in the 'batch_results' will have the key
  'error' with a value describing the error.
- `context` _(string: "")_ - Base64 encoded context for key derivation.
  Required if key derivation is enabled; currently only available with ed25519
  keys.
- `prehashed` _(bool: false)_ - Set to `true` when the input is already hashed.
  If the key type is `rsa-2048`, `rsa-3072` or `rsa-4096`, then the algorithm used to hash
  the input should be indicated by the `hash_algorithm` parameter. Just as the
  value to sign should be the base64-encoded representation of the exact binary
  data you want signed, when set, `input` is expected to be base64-encoded
  binary hashed data, not hex-formatted. (As an example, on the command line,
  you could generate a suitable input via `openssl dgst -sha256 -binary | base64`.)
- `signature_algorithm` _(string: "pss")_: When using a RSA key, specifies the RSA signature algorithm to use for signing.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#signature_algorithm-1) for supported values.
- `marshaling_algorithm` _(string: "asn1")_: Specifies the way in which the signature should be marshaled. This currently only applies to ECDSA keys.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#marshaling_algorithm-1) for supported values.
- `salt_length` _(string: "auto")_ – The salt length used to sign. This currently only applies to the RSA PSS signature scheme.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#salt_length-1) for supported values.

### Encrypt Config `encrypt`

- `name` _(string: test)_ – Specifies the name of the encryption key to
  encrypt against. This is specified as part of the URL.
- `plaintext` _(string: "")_ – Specifies **base64 encoded** plaintext to
  be encoded.
- `associated_data` _(string: "")_ - Specifies **base64 encoded** associated
  data (also known as additional data or AAD) to also be authenticated with
  AEAD cphers (`aes128-gcm96`, `aes256-gcm`, and `chacha20-poly1305`).
- `context` _(string: "")_ – Specifies the **base64 encoded** context for key
  derivation. This is required if key derivation is enabled for this key.
- `key_version` _(int: 0)_ – Specifies the version of the key to use for
  encryption. If not set, uses the latest version. Must be greater than or
  equal to the key's `min_encryption_version`, if set.
- `nonce` _(string: "")_ – Specifies the **base64 encoded** nonce value. This
  must be provided if convergent encryption is enabled for this key and the key
  was generated with Vault 0.6.1. Not required for keys created in 0.6.2+. The
  value must be exactly 96 bits (12 bytes) long and the user must ensure that
  for any given context (and thus, any given encryption key) this nonce value is
  **never reused**.
- `reference` _(string: "")_ -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using ‘batch_input’ below.
- `batch_input` _([]interface{}: nil)_ – Specifies a list of items to be
  encrypted in a single batch. When this parameter is set, if the parameters
  'plaintext', 'context' and 'nonce' are also set, they will be ignored.
  Any batch output will preserve the order of the batch input.
- `type` _(string: "aes256-gcm96")_ –This parameter is required when encryption
  key is expected to be created. When performing an upsert operation, the type
  of key to create.
- `convergent_encryption` _(string: "")_ – This parameter will only be used when
  a key is expected to be created. Whether to support convergent encryption.
  This is only supported when using a key with key derivation enabled and will
  require all requests to carry both a context and 96-bit (12-byte) nonce. The
  given nonce will be used in place of a randomly generated nonce. As a result,
  when the same context and nonce are supplied, the same ciphertext is
  generated. It is _very important_ when using this mode that you ensure that
  all nonces are unique for a given context. Failing to do so will severely
  impact the ciphertext's security.
- `partial_failure_response_code` _(int: 400)_ Ordinarily, if a batch item fails
  to encrypt due to a bad input, but other batch items succeed, the HTTP response
  code is 400 (Bad Request).  Some applications may want to treat partial failures
  differently.  Providing the parameter returns the given response code integer
  instead of a failed status code in this case. If all values fail an error
  code is still returned.  Be warned that some failures (such as failure to
  decrypt) could be indicative of a security breach and should not be
  ignored.

### Decrypt Config `decrypt`

- `name` _(string: test)_ – Specifies the name of the encryption key to
  decrypt against. This is specified as part of the URL.
- `ciphertext` _(string: "")_ – Specifies the ciphertext to decrypt.
- `associated_data` _(string: "")_ - Specifies **base64 encoded** associated
  data (also known as additional data or AAD) to also be authenticated with
  AEAD ciphers (`aes128-gcm96`, `aes256-gcm`, and `chacha20-poly1305`).
- `context` _(string: "")_ – Specifies the **base64 encoded** context for key
  derivation. This is required if key derivation is enabled.
- `nonce` _(string: "")_ – Specifies a base64 encoded nonce value used during
  encryption. Must be provided if convergent encryption is enabled for this key
  and the key was generated with Vault 0.6.1. Not required for keys created in
  0.6.2+.
- `reference` _(string: "")_ -
  A user-supplied string that will be present in the `reference` field on the
  corresponding `batch_results` item in the response, to assist in understanding
  which result corresponds to a particular input. Only valid on batch requests
  when using ‘batch_input’ below.
- `batch_input` _([]interface{}: nil)_ – Specifies a list of items to be
  decrypted in a single batch. When this parameter is set, if the parameters
  'ciphertext', 'context' and 'nonce' are also set, they will be ignored.
  Any batch output will preserve the order of the batch input.
- `partial_failure_response_code` _(int: 400)_ Ordinarily, if a batch item fails
  to encrypt due to a bad input, but other batch items succeed, the HTTP response
  code is 400 (Bad Request).  Some applications may want to treat partial failures
  differently.  Providing the parameter returns the given response code integer
  instead of a failed status code in this case. If all values fail an error
  code is still returned.  Be warned that some failures (such as failure to
  decrypt) could be indicative of a security breach and should not be
  ignored.

## Example Configuration

```hcl
test "transit_sign" "transit_sign_test_1" {
    weight = 25
}

test "transit_verify" "transit_verify_test_1" {
    weight = 25
    config {
        verify {
            signature_algorithm = "pkcs1v15"
        }
    }
}

test "transit_encrypt" "transit_encrypt_test_1" {
    weight = 25
    config {
      payload_len = 128
      context_len = 32
      keys {
        convergent_encryption = true
        derived = true
        type = "aes128-gcm96"
      }
    }
}

test "transit_decrypt" "transit_decrypt_test_1" {
    weight = 25
    config {
        payload_len = 64
    }
}

```

## Example Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-09-07T15:09:08.692-0400 [INFO]  vault-benchmark: setting up targets
2023-09-07T15:09:09.606-0400 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-09-07T15:09:11.609-0400 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                      count  rate         throughput   mean        95th%       99th%       successRatio
transit_decrypt_test_1  2158   1079.463900  1078.130128  2.914565ms  3.823562ms  5.052019ms  100.00%
transit_encrypt_test_1  2177   1089.316034  1088.447301  1.622277ms  2.404953ms  3.433451ms  100.00%
transit_sign_test_1     2112   1055.813825  1054.825166  2.996794ms  3.924258ms  5.151446ms  100.00%
transit_verify_test_1   2100   1050.706644  1049.699568  1.80163ms   2.645798ms  3.645347ms  100.00%
```
