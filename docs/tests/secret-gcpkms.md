# Google Cloud KMS Secrets Engine Benchmark

This benchmark tests the performance of the Google Cloud KMS secrets engine operations including encryption, decryption, signing, verification, and re-encryption.

## Test Types

The GCP KMS benchmark supports the following test types:

- `gcpkms_encrypt` - Tests encryption of plaintext data
- `gcpkms_decrypt` - Tests decryption of ciphertext data  
- `gcpkms_sign` - Tests signing of digest data
- `gcpkms_verify` - Tests verification of signatures
- `gcpkms_reencrypt` - Tests re-encryption of existing ciphertext with latest key version

## Benchmark Configuration Parameters

### General Configuration

- `payload_len` _(int: 128)_: Specifies the payload length to use for encryption/decryption/signing operations.

### GCP KMS Configuration (`config`)

- `credentials` _(string: <required>)_ - JSON credentials (either file contents or '@path/to/file'). 
  This value can also be provided with the `VAULT_BENCHMARK_GCPKMS_CREDENTIALS` environment variable.
- `scopes` _(array<string>: ["https://www.googleapis.com/auth/cloudkms"])_ - List of OAuth scopes to request when authenticating.

### Key Configuration (`key`)

- `key` _(string: "benchmark-key")_ - Name of the key in Vault.
- `key_ring` _(string: <required>)_ - Full Google Cloud resource ID of the key ring (e.g. projects/my-project/locations/global/keyRings/my-keyring). 
  This value can also be provided with the `VAULT_BENCHMARK_GCPKMS_KEY_RING` environment variable.
- `crypto_key` _(string: "")_ - Name of the crypto key to use. Defaults to the Vault key name if not specified.
- `purpose` _(string: "encrypt_decrypt")_ - Purpose of the key. Valid options: `asymmetric_decrypt`, `asymmetric_sign`, `encrypt_decrypt`.
- `algorithm` _(string: "symmetric_encryption")_ - Algorithm to use. Depends on key purpose:
  - For `encrypt_decrypt`: `symmetric_encryption`
  - For `asymmetric_decrypt`: `rsa_decrypt_oaep_2048_sha256`, `rsa_decrypt_oaep_3072_sha256`, `rsa_decrypt_oaep_4096_sha256`
  - For `asymmetric_sign`: `rsa_sign_pss_2048_sha256`, `ec_sign_p256_sha256`, `ec_sign_p384_sha384`, etc.
  
  **Note:** Different algorithms have different payload size limits. RSA algorithms support larger payloads than EC algorithms. Ensure your `payload_len` is compatible with the chosen algorithm.
- `protection_level` _(string: "software")_ - Level of protection. Valid values: `software`, `hsm`.
- `rotation_period` _(string: "")_ - Amount of time between crypto key version rotations (e.g. "72h").
- `labels` _(map<string>string: {})_ - Arbitrary key=value labels to apply to the crypto key.
- `mode` _(string: "create")_ - Key management mode. Valid values:
  - `create` - Create a new key with randomized suffix to prevent collisions (default).
  - `register` - Register an existing GCP KMS key without attempting to create it.

**Note:** All operations (encrypt, decrypt, sign, verify, reencrypt) use the key configured in this central `key` block. The benchmark automatically creates appropriate keys for each operation type and generates all test data (plaintext, ciphertext, digest, signature) based on the `payload_len` setting to ensure consistent performance testing.


## Prerequisites

Before running GCP KMS benchmarks, you need:

1. A Google Cloud Project with Cloud KMS API enabled
2. A service account with appropriate Cloud KMS permissions:
   - `roles/cloudkms.admin` (for creating keys)
   - `roles/cloudkms.cryptoKeyEncrypterDecrypter` (for encrypt/decrypt operations)
   - `roles/cloudkms.signerVerifier` (for sign/verify operations)
3. Service account credentials in JSON format
4. A Cloud KMS key ring created in your desired location

## Environment Variables

The following environment variables can be used to provide configuration:

- `VAULT_BENCHMARK_GCPKMS_CREDENTIALS` - Path to or contents of GCP service account credentials

### Creating vs Registering Keys

The GCP KMS benchmark supports two key management modes:

#### Create Mode (Default)
When `mode = "create"` (default), the benchmark will:
- Create new GCP KMS keys with randomized suffixes (e.g., `benchmark-key-a1b2c3d4`)
- Prevent key name collisions when running multiple benchmark sessions
- Automatically handle all key creation parameters

#### Register Mode
When `mode = "register"`, the benchmark will:
- Register existing GCP KMS keys that you've already created
- Require that the key already exists in Google Cloud KMS
- Use the exact key name specified without any randomization

## Example Configuration

### Basic Encryption/Decryption Test (Create Mode)
```hcl
test "gcpkms_encrypt" "encrypt_test" {
  weight = 50
  config {
    payload_len = 256
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "encrypt_decrypt"
      algorithm = "symmetric_encryption"
      mode = "create"  // Creates new key with randomized suffix
    }
  }
}
```

### Register Existing Key
```hcl
test "gcpkms_encrypt" "encrypt_test" {
  weight = 50
  config {
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key = "my-existing-key"
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      crypto_key = "my-existing-crypto-key"  // Must exist in GCP KMS
      mode = "register"  // Register existing key
    }
  }
}
```

### Basic Encryption/Decryption Test
```hcl
test "gcpkms_encrypt" "encrypt_test" {
  weight = 50
  config {
    payload_len = 256
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "encrypt_decrypt"
      algorithm = "symmetric_encryption"
    }
   
  }
}

test "gcpkms_decrypt" "decrypt_test" {
  weight = 50
  config {
    payload_len = 256
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "encrypt_decrypt"
      algorithm = "symmetric_encryption"
    }
  }
}
```

### Signing and Verification Test
```hcl
test "gcpkms_sign" "sign_test" {
  weight = 30
  config {
    payload_len = 64
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "asymmetric_sign"
      algorithm = "ec_sign_p256_sha256"
    }
  }
}

test "gcpkms_verify" "verify_test" {
  weight = 30
  config {
    payload_len = 64
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "asymmetric_sign"
      algorithm = "ec_sign_p256_sha256"
    }
  }
}
```

### Re-encryption Test
```hcl
test "gcpkms_reencrypt" "reencrypt_test" {
  weight = 40
  config {
    payload_len = 512
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "encrypt_decrypt"
      algorithm = "symmetric_encryption"
      rotation_period = "72h"
    }
  }
}
```

### Mixed Operations Test
```hcl
test "gcpkms_encrypt" "mixed_encrypt" {
  weight = 25
  config {
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
    }
  }
}

test "gcpkms_decrypt" "mixed_decrypt" {
  weight = 25
  config {
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
    }
  }
}

test "gcpkms_sign" "mixed_sign" {
  weight = 25
  config {
    payload_len = 64
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "asymmetric_sign"
      algorithm = "ec_sign_p256_sha256"
    }
  }
}

test "gcpkms_verify" "mixed_verify" {
  weight = 25
  config {
    payload_len = 64
    config {
      credentials = "@/path/to/service-account.json"
    }
    key {
      key_ring = "projects/my-project/locations/global/keyRings/my-keyring"
      purpose = "asymmetric_sign"
      algorithm = "ec_sign_p256_sha256"
    }
  }
}
```


## Example Usage
```bash 
$ vault-benchmark run  -config=config.hcl
2025-09-03T16:53:07.752+0530 [INFO]  vault-benchmark: setting up targets
2025-09-03T16:53:10.477+0530 [INFO]  vault-benchmark: starting benchmarks: duration=30s
2025-09-03T16:53:40.547+0530 [INFO]  vault-benchmark: cleaning up targets
2025-09-03T16:53:40.568+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op              count  rate      throughput  mean          95th%         99th%         successRatio
decrypt_test    6      0.260865  0.259967    104.685173ms  213.840083ms  213.840083ms  100.00%
encrypt_test    6      0.375000  0.373056    103.644277ms  204.625625ms  204.625625ms  100.00%
reencrypt_test  5      0.227274  0.226064    172.633441ms  221.8375ms    221.8375ms    100.00%
sign_test       5      0.238095  0.235019    195.709425ms  274.862334ms  274.862334ms  100.00%
verify_test     8      0.285712  0.285018    76.12412ms    89.418209ms   89.418209ms   100.00%
```


## Notes

- The benchmark automatically creates or registers the necessary keys during setup based on the operation type and mode
- For encryption/decryption/re-encryption tests, symmetric encryption keys are used
- For signing/verification tests, asymmetric signing keys are used
- **Key Cleanup**: GCP KMS keys created during benchmarks are **NOT automatically cleaned up** from Google Cloud. Only the Vault mount is removed during cleanup. You may need to manually delete keys from Google Cloud Console to avoid ongoing charges
- In `create` mode, key names are randomized to prevent collisions between multiple benchmark runs
- In `register` mode, you must ensure the specified crypto key already exists in Google Cloud KMS
- The service account must have sufficient permissions for the key ring location and project
- HSM-backed keys can be used by setting `protection_level = "hsm"` but may have additional costs and latency
- When using `register` mode, the `purpose` and `algorithm` fields are not required - the actual key properties are determined by the existing GCP KMS key
