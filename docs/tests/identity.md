# Identity Benchmark (`identity`)

This benchmark seeds Vault Identity objects (entities, and optionally groups,
aliases, and userpass users) during setup, then drives the selected `workload`
during the attack phase.

## Test Parameters

### Configuration `config`

- `workload` `(string: "populate")` - Attack-phase workload. One of:
  - `populate` - Seed only; objects are always kept regardless of the global `cleanup` flag, so this can build a persistent bloat dataset.
  - `login` - Log in as randomly selected users from the login pool. Requires `login_users > 0` and `alias_count > 0`.
  - `group_read` - Read randomly selected groups by id. Requires `group_count > 0`.
- `entity_count` `(int: 1000)` - Number of Identity entities to create during setup. Primary scale axis.
- `alias_count` `(int: 0)` - Number of entities (the first `alias_count`) that get a userpass alias. Must be `<= entity_count`; pairs with `login_users` to make entities loginable.
- `login_users` `(int: 100)` - Sample of users verified at setup (and, for the `login` workload). This checks alias resolution is correct; leave it at the default unless you have a specific reason to change it -- corruption is typically systemic, so a small sample catches it about as reliably as a large one, independent of `entity_count`.
- `group_count` `(int: 0)` - Number of internal groups to create; `0` creates none. Pairs with an optional `groups` block that only matters when `group_count > 0`, controlling how members are assigned:
  - omitted / `preset = "balanced"` (default) - members spread evenly across all groups
  - `preset = "empty"` - groups created with no members
  - `preset = "full"` - every group holds all entities
  - `count = N, size = M` - only `N` groups get `M` members each, the rest are empty

## Example HCL

Log in as seeded users, validating that aliases resolve correctly:

```hcl
test "identity" "identity_login" {
  weight = 100
  config {
    workload     = "login"
    entity_count = 1000
    alias_count  = 1000
    # verification sample; leave as-is unless you have a reason to change it.
    # (every seeded user shares password "id-pw", handy for manual debugging)
    login_users  = 100
  }
}
```

Read groups by id under load, spreading entities evenly across groups:

```hcl
test "identity" "identity_group_read" {
  weight = 100
  config {
    workload     = "group_read"
    entity_count = 1000
    group_count  = 1000
  }
}
```

Fill only some groups to a fixed capacity -- 50 of the 1000 groups hold 20
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

Seed a persistent bloat dataset:

```hcl
test "identity" "identity_seed" {
  weight = 100
  config {
    # populate always keeps its objects, and the attack phase still runs for
    # the full global `duration` (nothing to skip to) -- keep duration short,
    # e.g. "1s".
    workload     = "populate"
    entity_count = 10000
    alias_count  = 10000
  }
}
```

