# AppRole Auth Configuration Options

This benchmark tests the performance of logins using the AppRole auth method.

## Test Parameters (minimum 1 required)

- `pct_approle_login`: percent of requests that are approle logins

## Example Usage

```bash
$ ./benchmark-vault -pct_approle_login=100
op             count   rate          throughput    mean       95th%       99th%       successRatio
approle login  152174  15217.447491  15216.776175  648.864µs  1.372863ms  2.330503ms  100.00%
```
