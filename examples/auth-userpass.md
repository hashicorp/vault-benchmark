# Userpass Auth Configuration Options
This benchmark tests the performance of logins using the userpass auth method.

## Test Parameters (minimum 1 required)
- `pct_userpass_login`: percent of requests that are userpass logins

## Additional Parameters
- `userpass_role_config` _(required)_: path to JSON file containing Vault userpass configuration.  Configuration options can be found in the [Userpass API documentation](https://developer.hashicorp.com/vault/api-docs/auth/userpass).  However, note that only a subset of the parameters are supported including: `password`, `secret_id_ttl`, `token_ttl`, `token_max_ttl`, `token_policies`, `token_type`, `token_explicit_max_ttl`.  `password` is the only required parameter. Example configuration files can be found in the [userpass configuration directory](/example-configs/userpass/).

### Default Redis Role Configuration

```json
{
    "role_name": "benchmark-role",
    "password": "password",
    "token_ttl": "1h",
    "token_max_ttl": "2h",
    "token_policies": ["root"],
    "token_explicit_max_ttl": "3h",
    "token_type": "service"
}
```

### Example Usage

```bash
$ benchmark-vault \
    -vault_addr=http://localhost:8200 \
    -vault_token=dev \
    -pct_userpass_login=100 \
    -userpass_role_config=./example-configs/userpass/userpass_role_config.json \

op              count  rate        throughput  mean         95th%       99th%        successRatio
userpass login  1290   128.908289  128.017601  77.861585ms  88.85753ms  97.332523ms  100.00%
```