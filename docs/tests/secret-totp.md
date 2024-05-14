# TOTP Secret Benchmark

This benchmark tests the performance of the TOTP secrets engine. It creates a number of TOTP secrets on the configured mount and generates a set of keys.

## Test Parameters

### Configuration `config`

- `numkeys` `(int: 1000)` - this is the number of TOTP secrets we are going to write to the secrets engine before we test
- `keysize` `(int: 20)` - the size of the individual keys to write

## Example Configuration

```hcl
test "totp_read" "totp_read_test" {
    weight = 50
    config {
        numkeys = 100
    }
}

test "totp_write" "totp_write_test" {
    weight = 50
    config {
        numkeys = 10
        keysize = 100
    }
}
```

## Exmaple Usage

```bash
$ vault-benchmark run -config=config.hcl
2023-11-10T10:47:09.170+0100 [INFO]  vault-benchmark: setting up targets
2023-11-10T10:47:09.822+0100 [INFO]  vault-benchmark: starting benchmarks: duration=30s
2023-11-10T10:47:39.836+0100 [INFO]  vault-benchmark: cleaning up targets
2023-11-10T10:47:39.838+0100 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op               count  rate        throughput  mean         95th%        99th%        successRatio
totp_read_test   22549  751.865881  751.758572  1.007648ms   3.666889ms   5.977594ms   100.00%
totp_write_test  22791  759.675871  759.352465  12.166073ms  19.550502ms  25.294974ms  100.00%
```
