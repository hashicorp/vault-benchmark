# Identity Benchmark (`identity`)

This benchmark seeds Vault Identity objects during setup and, when a workload is
selected, drives that workload during the attack phase. It creates entities,
optional groups, and optional userpass links (users and/or aliases), and can
validate that logins resolve to the seeded entities. Cleanup depends on the
workload (see Notes).

## Test Parameters

### Configuration `config`

- `workload` `(string: "populate")` - Attack-phase workload. One of:
  - `populate` - Seed only; the attack phase just hits `sys/health` and the seeded objects are always kept (even if the global `cleanup` flag is on) so they can be reused as a bloat dataset. Use a short `duration` (see Notes).
  - `login` - Log in as randomly selected users from the login pool. Requires `login_users > 0` and `alias_count > 0` so logins resolve to seeded entities.
  - `group_read` - Read randomly selected groups by id. Requires `group_count > 0`.
- `entity_count` `(int: 1000)` - Number of Identity entities to create during setup. Primary scale axis.
- `alias_count` `(int: 0)` - Number of entities that also get a userpass alias, created for the first `alias_count` entities. On this single mount an alias maps 1:1 to an entity, so `alias_count` must be `<= entity_count`. (Giving one entity multiple aliases requires multiple mounts, a future feature.)
- `login_users` `(int: 100)` - Number of real (bcrypt) userpass users to create, for the first `login_users` entities. These users are the login-resolution verification sample at setup **and** the pool the `login` workload attacks. A user needs an alias to resolve, so the effective count is capped at `alias_count` (with `alias_count = 0` no users are created and no verification runs). Users are not part of the identity lifecycle; raising this only slows setup.
- `group_count` `(int: 0)` - Number of internal groups to create. `0` creates none.
- `groups` `(block)` - Optional block controlling how the `group_count` groups are filled with entities. Omit it for a balanced split. Set either a `preset` or `count`+`size` (not both):
  - `preset = "balanced"` (default) - Entities partitioned across all groups; every entity lands in one group (~`entity_count / group_count` members each).
  - `preset = "empty"` - All groups are created with no members.
  - `preset = "full"` - Every group holds all `entity_count` entities.
  - `count = N, size = M` - `N` of the groups hold `M` members each; the rest are empty. `N` must be `<= group_count` and `M <= entity_count`.

## Example HCL

Log in as seeded users, validating that aliases resolve correctly. Here 1000
entities are aliased and 100 of them get real users to attack:

```hcl
test "identity" "identity_login" {
  weight = 100
  config {
    workload     = "login"
    entity_count = 1000
    alias_count  = 1000
    login_users  = 100
  }
}
```

Read groups by id under load, spreading entities evenly across groups (an
omitted `groups` block does the same):

```hcl
test "identity" "identity_group_read" {
  weight = 100
  config {
    workload     = "group_read"
    entity_count = 1000
    group_count  = 1000
    groups {
      preset = "balanced"
    }
  }
}
```

Fill only some groups to a fixed capacity — 50 of the 1000 groups hold 20
members each, the rest are empty:

```hcl
test "identity" "identity_partial_groups" {
  weight = 100
  config {
    workload     = "group_read"
    entity_count = 1000
    group_count  = 1000
    groups {
      count = 50
      size  = 20
    }
  }
}
```

Seed a persistent bloat dataset — the `populate` workload keeps its objects even
in a mixed run where the global `cleanup` flag tears down other targets:

```hcl
test "identity" "identity_seed" {
  weight = 100
  config {
    workload     = "populate"
    entity_count = 10000
    alias_count  = 10000
  }
}
```

## Notes

- When `login_users` real users are created (bounded by `alias_count`), setup logs in as each one and fails if any login does not resolve to its expected entity, confirming the alias mapping is correct. The `login` workload always creates users, so it is always validated; other workloads validate only if `login_users` and `alias_count` are both set.
- The framework always drives an attack for the configured `duration`; there is no per-target early exit. With `workload = "populate"` the attack phase only hits `sys/health`, so set a short `duration` when you only want to seed objects.
- The `login` and `group_read` workloads honor the global `cleanup` flag (which requires `random_mounts`): when enabled it deletes created groups and entities and disables the run-scoped userpass mount, removing all created users in one call. The `populate` workload always keeps its seeded objects regardless of the global flag, so it can build a bloat dataset that survives a mixed run tearing down other targets. With the global flag off, all objects persist regardless.
- If setup fails partway through (e.g. a Vault error while creating entities), any objects created up to that point are left in place. This matches the framework, which does not tear down a target whose setup fails; benchmark runs use ephemeral Vault instances, so restart against a fresh instance.
