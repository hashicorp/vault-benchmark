# SSH Key Signing Secret Configuration Options

This benchmark will test throughput for SSH Key Signing. This test defaults to Client Key signing, but you can provide configuration for both the CA and Signer Role by using the `ssh_signer_ca_config_json` and `ssh_signer_role_config_json` flags respectively.

## Test Parameters (minimum 1 required)

- `pct_ssh_sign`: percent of requests that are SSH Client Key Sign operations

## Additional Parameters

- `ssh_ca_setup_delay` (_default=50ms): option to allow the SSH backend to be setup before the test starts.
- `ssh_ca_config_json`: can be used to specify a JSON file containing the SSH configuration
to use.  If this is not specified, a default configuration will be used (see below).

### Default SSH Configuration

`/ssh/config/ca`

```json
{
  "generate_signing_key": true,
  "key_type": "ssh-rsa",
  "key_bits": 0,
}
```

`/ssh/roles/:name`

```json
{
  "name": "benchmark-role",
  "port": 22,
 "key_bits": 1024,
 "algorithm_signer": "default",
 "not_before_duration": "30s",
 "key_type": "ca",
 "allow_user_certificates": true,
}
```

Please refer to the [SSH Secrets Engine](https://developer.hashicorp.com/vault/api-docs/secret/ssh) documenation for all available configuration options.

## Example Usage

```bash
$ benchmark-vault -pct_ssh_sign=100
op                count  rate         throughput   mean        95th%        99th%        successRatio
ssh pub key sign  12946  1294.587852  1293.681384  7.720743ms  10.379888ms  13.079202ms  100.00%
```
