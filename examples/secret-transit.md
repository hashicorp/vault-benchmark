# Transit Secret Configuration Options

This benchmark tests the performance of the transit operations.

## Test Parameters (minimum 1 required)

- `pct_transit_sign`: percent of requests that are sign requests to transit
- `pct_transit_verify`: percent of requests that are verify requests to transit
- `pct_transit_encrypt`: percent of requests that are encrypt requests to transit
- `pct_transit_decrypt`: percent of requests that are decrypt requests to transit

## Additional Parameters

- `transit_sign_setup_delay` (_default=50ms): allow the transit backend to be setup before the test starts when running sign tests
- `transit_verify_setup_delay` (_default=50ms): allow the transit backend to be setup before the test starts when running verify tests
- `transit_encrypt_setup_delay` (_default=50ms): allow the transit backend to be setup before the test starts when running encrypt tests
- `transit_decrypt_setup_delay` (_default=50ms): allow the transit backend to be setup before the test starts when running decrypt tests

## Example Usage

```bash
$ benchmark-vault -pct_transit_sign=50 -pct_transit_verify=50
op               count  rate         throughput   mean        95th%       99th%       successRatio
transit sign     54570  5457.386815  5456.674805  1.505858ms  2.679909ms  3.661053ms  100.00%
transit verify   26984  2698.373376  2698.320209  344.872µs   802.958µs   1.395324ms  100.00%
```
