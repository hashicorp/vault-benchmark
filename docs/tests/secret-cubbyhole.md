# Cubbyhole Secrets Engine Benchmark (`cubbyhole_read`, `cubbyhole_write`)
This benchmark will test reading from and writing to Vault's cubbyhole secrets engine. The cubbyhole secrets engine is used to store arbitrary secrets within the configured physical storage for Vault, but unlike the KV secrets engine, the secrets are scoped to the token that wrote them.

**Note:** The cubbyhole secrets engine is enabled by default at `/cubbyhole/`. It cannot be disabled, moved, or enabled multiple times.

## Test Types
- `cubbyhole_read`: Benchmarks reading secrets from cubbyhole
- `cubbyhole_write`: Benchmarks writing secrets to cubbyhole

## Benchmark Configuration Parameters
- `path` (`string: "my-path"`): The key path within cubbyhole where the path will be stored.

## Example HCL
```hcl
test "cubbyhole_read" "cubbyhole_read1" {
  weight = 50
  config {
    path = "my-read-path"
  }
}

test "cubbyhole_write" "cubbyhole_write1" {
  weight = 50
  config {
    path = "my-write-path"
  }
}
```

## Example Usage
```bash
$ vault-benchmark run -config=config.hcl
2025-08-20T10:27:46.162+0530 [INFO]  vault-benchmark: setting up targets
2025-08-20T10:27:46.163+0530 [INFO]  vault-benchmark: starting benchmarks: duration=10s
2025-08-20T10:27:56.164+0530 [INFO]  vault-benchmark: cleaning up targets
2025-08-20T10:27:56.164+0530 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op                count   rate          throughput    mean       95th%      99th%      successRatio
cubbyhole_read1   182270  18227.002962  18226.590357  257.346µs  397.11µs   553.035µs  100.00%
cubbyhole_write1  181810  18181.110147  18180.703351  275.704µs  442.921µs  630.051µs  100.00%
```

## Notes
- Cubbyhole secrets are tied to the specific token that creates them
- No mounting or unmounting is required as cubbyhole is built-in
- Each token has its own cubbyhole space that other tokens cannot access
- Perfect for storing temporary secrets or token-specific data