# AppRole Auth Configuration Options

This benchmark tests the performance of logins using the AppRole auth method.

## Test Parameters (minimum 1 required)

- `pct_approle_login`: percent of requests that are approle logins

## Additional Parameters

- `app_role_config` _(optional)_: path to JSON file containing Vault approle configuration.  Configuration options can be found in the [Approle Vault documentation](https://developer.hashicorp.com/vault/docs/auth/approle#configuration).  Example configuration files can be found in the [approle configuration directory](/configs/approle/).

## Example Usage

```bash
$ benchmark-vault \
    -pct_approle_login=100 \
    -app_role_config=./configs/approle/approle_config.json \

op             count   rate          throughput    mean       95th%       99th%       successRatio
approle login  155993  15599.254046  15598.592863  636.875µs  1.284479ms  1.963564ms  100.00%
```
