# KVV1 and KVV2 Secret Configuration Options

This benchmark tests the performance of KVV1 and/or KVV2.  It writes a set number of keys
(KV1 or KV2) to each mount, then reads them back.

## Test Parameters

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
Setting up targets...
Starting benchmarks. Will run for 5s...
Benchmark complete!
Target: http://127.0.0.1:8200
op                count  rate         throughput   mean       95th%      99th%       successRatio
kvv2_read_test    42086  8417.117502  8416.303933  587.767µs  993.278µs  1.542144ms  100.00%
kvv2_write_test   41935  8387.107623  8386.110707  586.623µs  982.795µs  1.534302ms  100.00%
```
