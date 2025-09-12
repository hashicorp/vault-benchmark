# IBM DB2 Secrets Engine Benchmark `ibmdb2_secret`

**Important Note**: For IBM DB2 dynamic credential generation, Vault does not support a direct database secrets engine connection. According to HashiCorp's official documentation ([DB2 Tutorial](https://developer.hashicorp.com/vault/docs/secrets/databases/db2#tutorial)), IBM DB2 dynamic credentials must be implemented using the **LDAP secrets engine** with DB2's group authentication plugin.

This benchmark configuration uses the LDAP dynamic secrets engine (`ldap_dynamic_secret`) to generate IBM DB2 credentials through LDAP user management, which integrates with DB2's authentication system.

## Implementation Approach

Instead of using a traditional database plugin, IBM DB2 credential generation works by:

1. **Using LDAP Secret Engine**: The `ldap_dynamic_secret` test type creates and manages LDAP users
2. **DB2 Group Authentication**: DB2 authenticates users through LDAP group membership
3. **Dynamic User Creation**: LDAP users are created with appropriate DB2 access permissions
4. **Automatic Cleanup**: Users are automatically removed when credentials expire

## Test Parameters

This test uses the standard LDAP dynamic secret configuration. See the [LDAP Dynamic Secret documentation](./secret-ldap-dynamic.md) for complete parameter details.

### Key Configuration Elements

- **Secret Engine**: Uses `ldap_dynamic_secret` instead of `ibmdb2_secret`
- **LDAP Integration**: Connects to LDAP server that manages DB2 user authentication
- **User Creation**: Creates LDAP users with DB2 group membership
- **Credential Lifecycle**: Manages user creation, authentication, and cleanup through LDAP

## Example Configuration

```hcl
test "ldap_dynamic_secret" "ibmdb2_ldap_test" {
    weight = 100
    config {
        secret {
            url      = "ldap://127.0.0.1:389"
            binddn   = "cn=admin,dc=example,dc=com"
            bindpass = "ldappass"
            schema   = "openldap"
            userdn   = "ou=users,dc=example,dc=com"
            connection_timeout = 10
            request_timeout = 30
        }
        role {
            role_name = "db2-dynamic"
            creation_ldif = "dn: uid={{.Username}},ou=users,dc=example,dc=com\nchangetype: add\nobjectClass: inetOrgPerson\ncn: {{.Username}}\nsn: {{.Username}}\nuid: {{.Username}}\nuserPassword: {{.Password}}"
            deletion_ldif = "dn: uid={{.Username}},ou=users,dc=example,dc=com\nchangetype: delete"
            rollback_ldif = "dn: uid={{.Username}},ou=users,dc=example,dc=com\nchangetype: delete"
            username_template = "vb_{{random 8}}_{{unix_time}}"
            default_ttl = 30
            max_ttl = 120
        }
    }
}
```

## Prerequisites

Before running this benchmark:

1. **LDAP Server**: Set up an LDAP server (OpenLDAP, Active Directory, etc.)
2. **DB2 Configuration**: Configure DB2 to authenticate users via LDAP groups
3. **LDAP Schema**: Ensure proper user and group structure in LDAP
4. **Network Access**: Verify connectivity between Vault, LDAP, and DB2

## Related Tests

- Use `target_secret_ldap_dynamic` for dynamic LDAP user creation
- Use `target_secret_ldap_static` for static LDAP credential rotation
- Both can be configured to work with DB2's LDAP authentication system

## Notes

- This approach leverages DB2's external authentication capabilities
- Performance depends on both LDAP server and DB2 authentication response times
- Consider LDAP connection pooling for high-throughput scenarios
- Monitor both LDAP and DB2 logs for authentication issues
