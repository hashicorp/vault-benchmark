# LDAP Auth Configuration Options

This benchmark will test LDAP Authentication to Vault. In order to use this test, configuration for the target LDAP server(s) must be provided as a JSON file using the `ldap_config_json` flag. The primary required fields are `url` and `groupdn` depending on the LDAP environment setup and desired connection method.

## Test Parameters (minimum 1 required)

- `pct_ldap_login`: percent of requests that are LDAP logins

## Additional Parameters

- `ldap_config_json` _(required)_: path to JSON file containing Vault LDAP configuration.  Configuration options can be found in the [LDAP Vault documentation](https://developer.hashicorp.com/vault/api-docs/auth/ldap#configure-ldap).  Example configuration files can be found in the [LDAP configuration directory](/configs/ldap/).
- `ldap_test_user_creds_json` _(required)_: path to JSON file containing test user credentials.  Example configuration files can be found in the [LDAP configuration directory](/configs/ldap/).

## Example Usage

```bash
$ vault-benchmark -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_ldap_login=100 \
    -ldap_config_json=/path/to/ldap/config.json \
    -ldap_test_user_creds_json=/path/to/ldap/test_user_creds.json
op          count  rate        throughput  mean         95th%         99th%        successRatio
LDAP login  1581   157.678405  156.778405    63.310542ms  193.090504ms  199.27467ms  100.00%
```

Please refer to the [Vault LDAP Auth documentation](https://developer.hashicorp.com/vault/api-docs/auth/ldap) for all available configuration options.
