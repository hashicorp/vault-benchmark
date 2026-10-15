# PKI Generate Key Benchmark (`pki_generate_key`)

This benchmark tests the performance of PKI key generation operations.

## Test Parameters

### Generate Key Config `generate_key`

- `type` `(string: "internal")` - Specifies the type of key to generate. If
  `internal`, the private key is generated inside Vault and cannot be retrieved
  later. If `exported`, the private key will be returned in the response.

- `key_type` `(string: "rsa")` - Specifies the desired key type; must be `rsa`,
  `ec`, `ed25519`, or `ml-dsa`.

- `key_bits` `(int: 0)` - Specifies the number of bits to use for the generated
  key. Allowed values are 0 (universal default); with `key_type=rsa`, allowed
  values are: 2048 (default), 3072, or 4096; with `key_type=ec`, allowed values
  are: 224, 256 (default), 384, or 521; ignored with `key_type=ed25519` and
  `key_type=ml-dsa`.

- `parameter_set` `(string: "")` - An ML-DSA key parameter set. Required when
  `key_type=ml-dsa`. Allowed values are `"44"`, `"65"`, and `"87"`.

- `key_name` `(string: "")` - Optionally specifies a name for the generated key.
  The global ref `default` may not be used as a name.

#### Managed Keys Parameters

See [Managed Keys](https://developer.hashicorp.com/vault/api-docs/secret/pki#managed-keys)
for additional details. One of the following parameters must be set when
`type=kms`.

- `managed_key_name` `(string: "")` - The managed key's configured name.

- `managed_key_id` `(string: "")` - The managed key's UUID.

## Example HCL Configuration

```hcl
test "pki_generate_key" "pki_generate_key_test1" {
  weight = 100
  config {
    setup_delay = "2s"

    generate_key {
      type     = "internal"
      key_type = "rsa"
      key_bits = 2048
    }
  }
}
```

### ML-DSA Example

```hcl
test "pki_generate_key" "pki_generate_key_mldsa" {
  weight = 100
  config {
    setup_delay = "2s"

    generate_key {
      type          = "internal"
      key_type      = "ml-dsa"
      parameter_set = "44"
    }
  }
}
```
