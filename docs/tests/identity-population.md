# Identity Population Benchmark (`identity_population`)

This benchmark creates Vault Identity entities during setup, and can optionally make them loginable so the attack phase drives userpass logins that resolve to those entities.

## Test Parameters

### Configuration `config`

- `entity_count` `(int: 10000)` - Number of Identity entities to create during setup.
- `name_prefix` `(string: "seed-entity")` - Prefix for generated entity names, created as `<name_prefix>-000001`, `<name_prefix>-000002`, etc.
- `progress_interval` `(int: 1000)` - How often to log progress during entity creation.
- `link_userpass_auth` `(bool: false)` - When `true`, setup also creates a userpass user and entity alias per entity (both named after the entity), and the attack phase logs in as randomly selected users. When `false`, this target only populates entities and the attack phase is a no-op health check.
- `userpass_mount` `(string: "userpass")` - Userpass auth mount used for created users and aliases. Enabled automatically if it does not already exist.

## Example HCL

```hcl
test "identity_population" "identity_population_login" {
  weight = 100
  config {
    entity_count       = 1000
    name_prefix        = "seed-entity"
    progress_interval  = 200
    link_userpass_auth = true
    userpass_mount     = "userpass"
  }
}
```

## Notes

- When `link_userpass_auth = true`, setup performs one login against the first user and fails if it does not resolve to that user's entity, confirming the alias mapping is correct.
- Cleanup is deferred in this MVP; created entities are not removed automatically.
