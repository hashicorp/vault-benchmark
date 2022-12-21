# LDAP Secret Configuration Options

This benchmark will test LDAP secret engine operations. In order to use this test, configuration for the LDAP server must be provided as a JSON file using the `ldap_config_json` flag. The primary required fields are the `url` and `binddn` for the user configured in LDAP for Vault to use, as well as the `bindpass` field that defines the password for the user.

This includes tests for both static and dynamic roles.

A static role configuration file can be passed via the `ldap_static_role_json` flag. A dynamic role configuration file can be passed via the `ldap_dynamic_role_json` flag.

## Test Parameters (minimum 1 required)

- `pct_ldap_static_role_read`: percent of requests that are LDAP reads
- `pct_ldap_static_role_rotate`: percent of requests that are LDAP static role rotations
- `pct_ldap_dynamic_role_read`: percent of requests that are LDAP dynamic credential generations

## Additional Parameters

- `ldap_config_json` _(required)_: path to JSON file containing Vault LDAP configuration.  Configuration options can be found in the [LDAP Vault documentation](https://developer.hashicorp.com/vault/api-docs/secret/ldap).
- `ldap_static_role_json`: path to LDAP benchmark static role configuration JSON file to use.
- `ldap_dynamic_role_json`: path to LDAP benchmark dynamic role configuration JSON file to use.

Example configuration files can be found in the [LDAP configuration directory](/configs/ldap/).

_Note: The `creation_ldif` and `deletion_ldif` fields are base64 encoded LDIFs. The `rollback_ldif` field is optional and is only used if the `rollback_on_failure` field is set to true._

### Example Usage

```bash
$ benchmark-vault \
    -vault_addr=http://localhost:8200 \
    -vault_token=root \
    -pct_ldap_dynamic_role_read=100 \
    -ldap_config_json=/path/to/ldap/config.json \
    -ldap_dynamic_role_json=/path/to/ldap/dynamic_role.json
op                    count  rate       throughput  mean          95th%         99th%         successRatio
LDAP dynamic read  687    68.602787  67.609274   146.945225ms  153.417724ms  176.005047ms  100.00%
```
