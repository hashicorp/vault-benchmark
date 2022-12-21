# Certificate Auth Configuration Options

This benchmark tests the performance of logins using the Certificate auth method.

## Test Parameters (minimum 1 required)

- `pct_cert_login`: percent of requests that are cert logins

## Example Usage

```bash
$ benchmark-vault -pct_cert_login=100
op          count   rate          throughput  mean       95th%      99th%       successRatio
cert login  319098  31909.905836  0.000000    303.255µs  695.622µs  1.497842ms  0.00%
```
