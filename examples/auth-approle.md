# AppRole Auth Configuration Options

This benchmark tests the performance of logins using the AppRole auth method.

## Test Parameters (minimum 1 required)

- `pct_approle_login`: percent of requests that are approle logins

## Additional Parameters

- `app_role_config` _(optional)_: path to JSON file containing Vault approle configuration.  Configuration options can be found in the [Approle API documentation](https://developer.hashicorp.com/vault/api-docs/auth/approle).  However, note that only a subset of the parameters are supported including: `secret_id_ttl`, `token_ttl`, `token_max_ttl`, `token_policies`, `token_type`. Example configuration files can be found in the [approle configuration directory](/example-configs/approle/).

## Example Usage

```bash
$ benchmark-vault \
    -pct_approle_login=100 \
    -app_role_config=./example-configs/approle/approle_config.json \

op             count   rate          throughput    mean       95th%       99th%       successRatio
approle login  155993  15599.254046  15598.592863  636.875µs  1.284479ms  1.963564ms  100.00%
```
