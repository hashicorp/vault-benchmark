# Identity Benchmark (`identity`)

This benchmark seeds Vault Identity objects during setup and, when a workload is
selected, drives that workload during the attack phase. It creates entities,
optional groups, and optional userpass links (users and/or aliases), can validate
that logins resolve to the seeded entities, and cleans up everything it created.

It consolidates the former `identity_population` and `identity_group_read`
targets: choose `workload = "login"` for the population/login benchmark,
`workload = "group_read"` for the group-read benchmark, or `workload = "none"` to
only seed objects.

## Test Parameters

### Configuration `config`

- `entity_count` `(int: 1000)` - Number of Identity entities to create during setup.
- `name_prefix` `(string: "entity")` - Prefix for generated object names. Entities are named `<name_prefix>-<run_id>-000001` and groups `<name_prefix>-group-<run_id>-000001`; the per-run id keeps names unique across concurrent runs while remaining index-addressable.
- `progress_interval` `(int: 1000)` - How often to log progress during entity creation.
- `workload` `(string: "none")` - Attack-phase workload. One of:
  - `none` - Seed only. The attack phase performs no identity work and only hits `sys/health`; use a short `duration` for seed-only runs (see Notes).
  - `login` - The attack phase logs in as randomly selected users. Requires `create_users = true` and `create_aliases = true`.
  - `group_read` - The attack phase reads randomly selected groups by id. Requires `group_count > 0`.
- `group_count` `(int: 0)` - Number of internal groups to create. `0` creates no groups.
- `group_size` `(int: 10)` - Number of entity members per group. Must be `> 0` and `<= entity_count` when `group_count > 0`.
- `create_aliases` `(bool: false)` - When `true`, link each entity to a userpass entity alias (named after the entity) so logins resolve to it. Enables the sampled login-resolution validation below.
- `create_users` `(bool: false)` - When `true`, create a userpass user per entity (named after the entity) so entities are loginable.
- `userpass_mount` `(string: "userpass")` - Userpass auth mount used for created users and aliases. Enabled automatically if it does not already exist. Required when `create_aliases` or `create_users` is set.
- `validation_samples` `(int: 100)` - Number of aliases randomly sampled at setup to verify login resolution when `create_aliases` is `true`. Clamped to `entity_count`. Because alias-linking failures are systematic, a fixed sample gives high confidence independent of `entity_count`; raise it for stricter checks or lower it for faster setup.

## Example HCL

Login workload (former `identity_population` with `link_auth = true`):

```hcl
test "identity" "identity_login" {
  weight = 100
  config {
    entity_count       = 1000
    name_prefix        = "entity"
    progress_interval  = 200
    workload           = "login"
    create_users       = true
    create_aliases     = true
    userpass_mount     = "userpass"
    validation_samples = 100
  }
}
```

Group-read workload (former `identity_group_read`):

```hcl
test "identity" "identity_group_read" {
  weight = 100
  config {
    entity_count   = 1000
    group_count    = 1000
    group_size     = 10
    workload       = "group_read"
    create_aliases = true
    userpass_mount = "userpass"
  }
}
```

Seed only (no attack-phase workload):

```hcl
test "identity" "identity_seed" {
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
