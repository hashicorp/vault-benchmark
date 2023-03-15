# Transit Secret Configuration Options

This benchmark tests the performance of the transit operations.

## Test Parameters

### Transit Config

- `convergent_encryption` _(bool: false)_: If enabled, the key will support convergent encryption, where the same plaintext creates the same ciphertext. This requires derived to be set to true. When enabled, each encryption(/decryption/rewrap/datakey) operation will derive a nonce value rather than randomly generate it.
- `derived` _(bool: false)_: Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this named key must provide a context which is used for key derivation.
- `type` _(string: "rsa-2048")_: Specifies the type of key to create.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#type) for supported values.
- `payload_len` _(int: 128)_: Specifies the payload length to use for encryption/decryption operations.
- `context_len` _(int: 32)_: Specifies the context length to use for encryption/decryption operations.
- `hash_algorithm` _(string: "sha2-256")_:  Specifies the hash algorithm to use for supporting key types (notably, not including ed25519 which specifies its own hash algorithm).  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#hash_algorithm) for supported values.
- `signature_algorithm` _(string: "pss")_: When using a RSA key, specifies the RSA signature algorithm to use for signing.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#signature_algorithm) for supported values.
- `marshaling_algorithm` _(string: "asn1")_: Specifies the way in which the signature should be marshaled. This currently only applies to ECDSA keys.  See [API docs](https://developer.hashicorp.com/vault/api-docs/secret/transit#marshaling_algorithm) for supported values.

## Example Configuration

```hcl
# Test selection and options
test "transit_sign" "transit_sign_test_1" {
    weight = 25
}

test "transit_verify" "transit_verify_test_1" {
    weight = 25
    config {
        signature_algorithm = "pkcs1v15"
    }
}

test "transit_encrypt" "transit_encrypt_test_1" {
    weight = 25
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
$ vault-benchmark run -config=example-configs/transit/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op                      count  rate         throughput   mean        95th%       99th%       successRatio
transit_decrypt_test_1  3610   1805.934082  1804.305380  2.140936ms  3.385891ms  4.669672ms  100.00%
transit_encrypt_test_1  3570   1785.412839  1784.967498  609.48µs    1.17847ms   1.82117ms   100.00%
transit_sign_test_1     3509   1755.252455  1753.604967  2.257936ms  3.614323ms  5.015208ms  100.00%
transit_verify_test_1   3453   1727.512538  1727.166507  615.155µs   1.183563ms  1.818366ms  100.00%
```
