# Identity Group Read Benchmark (`identity_group_read`)

This benchmark seeds Vault Identity objects during setup and, when a workload is
selected, drives that workload during the attack phase. It creates entities,
optional groups, and optional userpass links (users and/or aliases), and can
validate that logins resolve to the seeded entities. Cleanup depends on the
workload (see Notes).

## Test Parameters

### Configuration `config`

- `workload` `(string: "populate")` - Attack-phase workload. One of:
  - `populate` - Seed only; the attack phase just hits `sys/health` and the seeded objects are always kept (even if the global `cleanup` flag is on) so they can be reused as a bloat dataset. Use a short `duration` (see Notes).
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

Log in as seeded entities, validating that aliases resolve correctly:

```hcl
test "identity_group_read" "identity_login" {
  weight = 100
  config {
    workload       = "login"
    entity_count   = 1000
    create_users   = true
    create_aliases = true
  }
}
```

Read groups by id under load:

```hcl
test "identity_group_read" "identity_group_read" {
  weight = 100
  config {
    workload     = "group_read"
    entity_count = 1000
    group_count  = 1000
    group_size   = 10
  }
}
```

Seed a persistent bloat dataset — the `populate` workload keeps its objects even
in a mixed run where the global `cleanup` flag tears down other targets:

```hcl
test "identity_group_read" "identity_seed" {
  weight = 100
  config {
    workload     = "populate"
    entity_count = 10000
  }
}
```

## Notes

- When `create_aliases = true`, setup logs in against a random sample of created entities (see `validation_samples`) and fails if any login does not resolve to that entity, confirming the alias mapping is correct. The `login` workload requires aliases, so it is always validated.
- The framework always drives an attack for the configured `duration`; there is no per-target early exit. With `workload = "populate"` the attack phase only hits `sys/health`, so set a short `duration` when you only want to seed objects.
- The `login` and `group_read` workloads honor the global `cleanup` flag (which requires `random_mounts`): when enabled it deletes created groups and entities and disables the run-scoped userpass mount, removing all created users in one call. The `populate` workload always keeps its seeded objects regardless of the global flag, so it can build a bloat dataset that survives a mixed run tearing down other targets. With the global flag off, all objects persist regardless.
