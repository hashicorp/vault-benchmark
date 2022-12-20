# PKI Secret Configuration Options

This benchmark tests the performance of PKI issue operations.

## Test Parameters (minimum 1 required)

- `pct_pki_issue`: percent of requests that are pki issues

## Additional Parameters

- `pki_setup_delay` (_default=50ms): option to allow the PKI backend to be setup before the test starts.
- `pki_config_json`: can be used to specify a JSON file containing the PKI configuration
to use.  If this is not specified, a default configuration will be used (see below).

### Default PKI Configuration

```json
{
  "root_key_type": "rsa",
  "root_key_bits": 2048,
  "int_key_type": "rsa",
  "int_key_bits": 2048,
  "leaf_key_type": "rsa",
  "leaf_key_bits": 2048,
  "leaf_store": false,
  "leaf_lease": false
}
```

Additional configuration examples can be found in the [pki configuration directory](/configs/pki/).

## Example Usage

```bash
$ ./benchmark-vault -pct_pki_issue=100
op         count  rate       throughput  mean          95th%         99th%         successRatio
pki issue  770    76.912068  75.437967   130.886886ms  281.848785ms  424.038003ms  100.00%
```
