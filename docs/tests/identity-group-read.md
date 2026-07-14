# Identity Group Read Benchmark (`identity_group_read`)

This benchmark seeds Vault Identity objects during setup and, when a workload is
selected, drives that workload during the attack phase. It creates entities,
optional groups, and optional userpass links (users and/or aliases), can validate
that logins resolve to the seeded entities, and cleans up everything it created.

It absorbs the former `identity_population` target: choose `workload = "login"`
for the population/login benchmark, `workload = "group_read"` for the group-read
benchmark, or `workload = "none"` to only seed objects.

## Test Parameters

### Configuration `config`

- `workload` `(string: "none")` - Attack-phase workload. One of:
  - `none` - Seed only; the attack phase just hits `sys/health`. Use a short `duration` (see Notes).
  - `login` - Log in as randomly selected users. Requires `create_users = true` and `create_aliases = true`.
  - `group_read` - Read randomly selected groups by id. Requires `group_count > 0`.
- `entity_count` `(int: 1000)` - Number of Identity entities to create during setup.
- `create_users` `(bool: false)` - Create a userpass user per entity so entities are loginable.
- `create_aliases` `(bool: false)` - Link each entity to a userpass alias so logins resolve to it. Enables the sampled login-resolution validation.
- `userpass_mount` `(string: "userpass")` - Userpass mount for created users/aliases; enabled automatically if absent. Required when `create_users` or `create_aliases` is set.
- `group_count` `(int: 0)` - Number of internal groups to create. `0` creates none.
- `group_size` `(int: 10)` - Entity members per group. Must be `> 0` and `<= entity_count` when `group_count > 0`.
- `validation_samples` `(int: 100)` - Aliases sampled at setup to verify login resolution when `create_aliases` is set. Clamped to `entity_count`; a fixed sample gives high confidence independent of `entity_count`.
- `progress_interval` `(int: 1000)` - How often to log progress during entity creation.

## Example HCL

Login workload (former `identity_population` with `link_auth = true`):

```hcl
test "identity_group_read" "identity_login" {
  weight = 100
  config {
    workload           = "login"
    entity_count       = 1000
    create_users       = true
    create_aliases     = true
    userpass_mount     = "userpass"
    validation_samples = 100
    progress_interval  = 200
  }
}
```

Group-read workload (former `identity_group_read`):

```hcl
test "identity_group_read" "identity_group_read" {
  weight = 100
  config {
    workload       = "group_read"
    entity_count   = 1000
    create_aliases = true
    userpass_mount = "userpass"
    group_count    = 1000
    group_size     = 10
  }
}
```

Seed only (no attack-phase workload):

```hcl
test "identity_group_read" "identity_seed" {
  weight = 100
  config {
    entity_count = 10000
    workload     = "none"
  }
}
```

## Notes

- When `create_aliases = true`, setup logs in against a random sample of created entities (see `validation_samples`) and fails if any login does not resolve to that entity, confirming the alias mapping is correct. The `login` workload requires aliases, so it is always validated.
- The framework always drives an attack for the configured `duration`; there is no per-target early exit. With `workload = "none"` the attack phase only hits `sys/health`, so set a short `duration` when you only want to seed objects.
- Cleanup (enabled with the global `cleanup` flag, which requires `random_mounts`) deletes created groups and entities and disables the run-scoped userpass mount, which removes every linked and probe user in a single call.
