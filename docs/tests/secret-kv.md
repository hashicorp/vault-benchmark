# KVV1 and KVV2 Secret Benchmark

This benchmark tests the performance of KVV1 and/or KVV2.  It writes a set number of keys (KV1 or KV2) to each mount, then reads them back.

## Test Parameters

### Configuration `config`

- `numkvs` `(int: 1000)` - if any kvv1 or kvv2 requests are specified,
then this many keys will be written during the setup phase.  The read operations
will read from these keys, and the write operations overwrite them.
- `kvsize` `(int: 1)`:  the size of the key and value to write.

## Example Configuration

```hcl
test "kvv2_read" "kvv2_read_test" {
    weight      = 50

    config {
        setup_delay = "2s"
        numkvs      = 100
    }
}

test "kvv2_write" "kvv2_write_test" {
    weight      = 50

    config {
        setup_delay = "2s"
        numkvs      = 10
        kvsize      = 1000
    }
}
```
