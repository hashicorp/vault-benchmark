# KVV1 and KVV2 Secret Benchmark 
This benchmark tests the performance of KVV1 and/or KVV2.  It writes a set number of keys (KV1 or KV2) to each mount, then reads them back.

## Test Parameters
### Configuration `config`
- `numkvs` (_default=1000_): if any kvv1 or kvv2 requests are specified,
then this many keys will be written during the setup phase.  The read operations
will read from these keys, and the write operations overwrite them.
- `kvsize` (_default=1_):  the size of the key and value to write.

## Example Configuration
```hcl
test "kvv2_read" "kvv2_read_test" {
    weight = 50
    config {
        numkvs = 100
    }
}

test "kvv2_write" "kvv2_write_test" {
    weight = 50
    config {
        numkvs = 10
        kvsize = 1000
    }
}
```

## Example Usage
```bash
$ vault-benchmark run -config=config.hcl
2023-05-01T15:46:10.195-0500 [INFO]  vault-benchmark: setting up targets
2023-05-01T15:46:14.295-0500 [INFO]  vault-benchmark: starting benchmarks: duration=2s
2023-05-01T15:46:16.297-0500 [INFO]  vault-benchmark: benchmark complete
Target: http://127.0.0.1:8200
op               count  rate         throughput   mean        95th%       99th%       successRatio
kvv2_read_test   7372   3685.483957  3684.373734  1.350193ms  1.932011ms  2.427874ms  100.00%
kvv2_write_test  7476   3738.104588  3736.361605  1.3383ms    1.94206ms   2.438648ms  100.00% 
```
