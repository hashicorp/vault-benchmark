# System Status Configuration Options

## Example Configuration

```hcl
test "ha_status" "ha_status_test_1" {
    weight = 30
}

test "seal_status" "seal_status_test_1" {
    weight = 30
}

test "metrics" "metrics_test_1" {
    weight = 40
}
```

### Example Usage

```bash
$ vault-benchmark run -config=example-configs/status/config.hcl
Setting up targets...
Starting benchmarks. Will run for 10s...
Benchmark complete!
Target: http://127.0.0.1:8200
op                  count  rate         throughput   mean       95th%       99th%       successRatio
ha_status_test_1    68233  6823.507691  6823.057809  596.062µs  1.31989ms   2.008227ms  100.00%
metrics_test_1      91391  9139.507851  9139.160661  326.684µs  684.966µs   994.849µs   100.00%
seal_status_test_1  68126  6812.806087  6812.420493  412.102µs  1.055864ms  1.577493ms  100.00%
```
