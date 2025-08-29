# TOTP Secrets Engine Benchmark (`totp_create`, `totp_read`, `totp_generate`)

This benchmark tests the performance of Vault's TOTP (Time-based One-Time Password) secrets engine. The TOTP secrets engine enables Vault to function as a TOTP provider in multiple roles:
- **Key Creator**: Creates new TOTP keys with configurable parameters (issuer, account, algorithm, etc.)
- **Key Reader**: Reading TOTP key metadata and configuration information
- **Code Generator**: Similar to Google Authenticator, generating time-based codes for authentication

**Note:** The TOTP secrets engine must be enabled before running these tests.

## Test Types
- `totp_create`: Benchmarks creating new TOTP keys with unique names and metadata
- `totp_read`: Benchmarks reading TOTP key information and metadata
- `totp_generate`: Benchmarks generating TOTP codes from existing keys

## Benchmark Configuration Parameters

### Configuration Options
- `key_name` (`string: "benchmark-key"`): The name of the TOTP key to create or use for code generation.
- `issuer` (`string: "Vault Benchmark"`): The issuer name for the TOTP key (appears in authenticator apps).
- `account_name` (`string: "benchmark-user"`): The account name for the TOTP key.
- `algorithm` (`string: "SHA1"`): The hashing algorithm to use (SHA1, SHA256, or SHA512).
- `digits` (`int: 6`): The number of digits in the generated TOTP code (typically 6 or 8).
- `period` (`int: 30`): The time period in seconds for which each TOTP code is valid.
- `generate` (`bool: true`): Whether to auto-generate the secret key during TOTP key creation.

## Example HCL Configuration

```hcl
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "30s"
cleanup = true

test "totp_create" "totp_create1" {
  weight = 34
  config {
    key_name = "benchmark-create-key"
    issuer = "Vault Benchmark"
    account_name = "test@user.com"
    algorithm = "SHA1"
    digits = 6
    period = 30
    generate = true
  }
}

test "totp_read" "totp_read1" {
  weight = 33
  config {
    key_name = "benchmark-read-key"
    issuer = "Vault Benchmark"
    account_name = "test@user.com"
    algorithm = "SHA1"
    digits = 6
    period = 30
  }
}

test "totp_generate" "totp_generate1" {
  weight = 33
  config {
    key_name = "benchmark-generate-key"
    issuer = "Vault Benchmark"
    account_name = "test@user.com"
    algorithm = "SHA1"
    digits = 6
    period = 30
    generate = true
  }
}
```

## Example Usage

```bash
$ vault-benchmark run -config=totp-config.hcl
2025-08-26T11:19:30.325+0530 [INFO]  vault-benchmark: setting up targets
2025-08-26T11:19:30.337+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-08-26T11:19:40.340+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op              count  rate         throughput   mean        95th%       99th%       successRatio
totp_create1    20128  2012.965340  2012.194472  4.525332ms  6.165336ms  6.717629ms  100.00%
totp_generate1  19550  1955.293131  1955.261801  228.439µs   468.116µs   684.967µs   100.00%
totp_read1      19339  1933.722976  1933.691628  224.624µs   463.29µs    657.167µs   100.00%
```

## Notes

- **TOTP Key Creation**: Creating TOTP keys involves cryptographic operations and key storage (~4-5ms per operation)
- **Code Generation**: Generating TOTP codes is fast as it only requires hash computation (~230µs per operation)
- **Key Reading**: Reading TOTP key metadata is efficient with optimized key patterns (~225µs per operation)
- **Success Ratios**: 
  - Create operations: 100% (deterministic)
  - Generate operations: 100% (deterministic)
  - Read operations: 100% (deterministic with predictable key patterns)
- **Mount Path**: The TOTP secrets engine must be mounted before running benchmarks (default path is `/totp/`)
- **Key Persistence**: Created TOTP keys are stored in Vault and can be reused across benchmark runs
- **Security**: TOTP keys contain sensitive cryptographic material and should be cleaned up after benchmarking
- **Optimization Features**:
  - Pre-computed URL patterns for improved performance
  - Pre-marshaled JSON for create operations
  - Simplified key naming patterns for reliable key access
  - Index-based key rotation for create operations
