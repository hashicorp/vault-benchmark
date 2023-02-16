# KVV1 and KVV2 Secret Configuration Options

This benchmark tests the performance of KVV1 and/or KVV2.  It writes a set number of keys
(KV1 or KV2) to each mount, then reads them back.

## Test Parameters (minimum 1 required)

- `pct_kvv1_write`: percent of requests that are kvv1 writes
- `pct_kvv1_read`: percent of requests that are kvv1 reads
- `pct_kvv2_write`: percent of requests that are kvv2 writes
- `pct_kvv2_read`: percent of requests that are kvv2 reads

## Additional Parameters

- `numkvs` (_default=1000_): if any kvv1 or kvv2 requests are specified,
then this many keys will be written during the setup phase.  The read operations
will read from these keys, and the write operations overwrite them.
- `kvsize` (_default=1_):  the size of the key and value to write.

## Example Usage

```bash
$ vault-benchmark \
    -pct_kvv1_read=75 \
    -pct_kvv1_write=25 \
    -numkvs=100 \
    -kvsize=10
op          count   rate          throughput    mean       95th%      99th%       successRatio
kvv1 read   207078  20707.991723  20707.303112  342.588µs  792.455µs  1.79457ms   100.00%
kvv1 write  69309   6931.423438   6931.229002   382.028µs  861.062µs  2.103818ms  100.00%

$ vault-benchmark -pct_kvv2_read=50 -pct_kvv2_write=50
op          count  rate         throughput   mean       95th%       99th%       successRatio
kvv2 read   99087  9909.216270  9908.109187  396.701µs  927.28µs    1.954493ms  100.00%
kvv2 write  98077  9807.787657  9807.321928  604.503µs  1.348884ms  2.790181ms  100.00%
```
