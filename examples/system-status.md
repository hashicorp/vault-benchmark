# System Status Configuration Options

## Test Parameters (minimum 1 required)

- `pct_ha_status`: percent of requests that are ha status requests (/sys/ha-status)
- `pct_seal_status`: percent of requests that are seal status requests (/sys/seal-status)
- `pct_metrics`: percent of requests that are read requests to metrics (/sys/metrics)

## Example Usage

```bash
$ benchmark-vault -pct_ha_status=100
op         count   rate          throughput    mean       95th%      99th%       successRatio
ha status  307299  30731.021169  30728.013045  316.743µs  717.639µs  1.705715ms  100.00%

$ benchmark-vault -pct_seal_status=100
op           count   rate          throughput    mean       95th%      99th%       successRatio
seal status  510343  51034.352310  51033.783069  173.612µs  434.735µs  1.116063ms  100.00%

$ benchmark-vault -pct_metrics=100
op       count   rate          throughput    mean       95th%      99th%       successRatio
metrics  305119  30512.043407  30509.221162  311.575µs  853.498µs  2.214729ms  100.00%
```
