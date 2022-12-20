# Signed SSH Secret Configuration Options

This benchmark tests the performance of Signed SSH Certificate issue operations.

## Test Parameters (minimum 1 required)

- `pct_ssh_ca_issue`: percent of requests that are ssh issue certs

## Additional Parameters

- `ssh_ca_setup_delay` (_default=50ms): option to allow the SSH backend to be setup before the test starts.
- `ssh_ca_config_json`: can be used to specify a JSON file containing the SSH configuration
to use.  If this is not specified, a default configuration will be used (see below).

### Default SSH Configuration

```json
{
  "ca_key_type": "rsa",
  "ca_key_bits": 2048,
  "leaf_key_type": "rsa",
  "leaf_key_bits": 2048
}
```

Additional configuration examples can be found in the [ssh configuration directory](/configs/ssh/).

## Example Usage

```bash
$ ./benchmark-vault -pct_ssh_ca_issue=100
op         count   rate          throughput  mean       95th%      99th%       successRatio
ssh issue  300282  30028.310228  0.000000    324.823µs  752.144µs  1.601211ms  0.00%
```
