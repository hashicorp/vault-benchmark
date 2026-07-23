# Identity Benchmark (`identity`)

This benchmark seeds Vault Identity objects (entities, and optionally groups,
aliases, userpass users, and ACL policies) during setup, then drives the
selected `workload` during the attack phase.

## Test Parameters

### Configuration `config`

- `workload` `(string: "populate")` - Attack-phase workload. One of:
  - `populate` - Seed only; objects are always kept regardless of the global `cleanup` flag, so this can build a persistent bloat dataset.
  - `login` - Log in as randomly selected users from the login pool. Requires `login_users > 0` and `alias_count > 0`.
  - `group_read` - Read randomly selected groups by id. Requires `group_count > 0`.
- `entity_count` `(int: 1000)` - Number of Identity entities to create during setup. Primary scale axis.
- `alias_count` `(int: 0)` - Total number of aliases to create across entities. Pairs with `login_users` to make entities loginable. When `alias_count > entity_count`, entities receive more than one alias (e.g. `alias_count = 3000` with `entity_count = 1000` gives 3 aliases per entity under `balanced`). The benchmark provisions one userpass auth mount per alias slot, so `ceil(alias_count / entity_count)` mounts are created. See also the optional `aliases` block below.
- `login_users` `(int: 100)` - Sample of users verified at setup (and, for the `login` workload). This checks alias resolution is correct; leave it at the default unless you have a specific reason to change it -- corruption is typically systemic, so a small sample catches it about as reliably as a large one, independent of `entity_count`.
- `group_count` `(int: 0)` - Number of internal groups to create; `0` creates none. Pairs with an optional `groups` block (see below) that controls how members are assigned.
- `policy_count` `(int: 0)` - Number of Vault ACL policies to create; `0` creates none. Each policy is a minimal `path "secret/*" { capabilities = ["read"] }` placeholder. Pairs with an optional `policies` block (see below) that controls which entities and groups receive them.

### Block `aliases`

Controls how the `alias_count` aliases are distributed across entities. Only
relevant when `alias_count > 0`. Omitting the block is equivalent to
`preset = "balanced"`.

- `preset` `(string: "balanced")` - Named distribution strategy. One of:
  - `balanced` (default) - aliases spread evenly across all entities (`ceil(alias_count / entity_count)` per entity)
  - `empty` - no aliases are created regardless of `alias_count`
  - `full` - every entity receives `alias_count` aliases each. Because `alias_count` is used directly as the aliases-per-entity cap, `alias_count` userpass mounts are created (one per slot). Note: with `full` the total aliases written is `entity_count × alias_count`, not just `alias_count`.
- `count` `(int: 0)` - Manual mode: number of entities that receive aliases. Cannot be combined with `preset`.
- `size` `(int: 0)` - Manual mode: number of aliases each filled entity receives. Cannot be combined with `preset`.

### Block `groups`

Controls how entities are assigned as members of the `group_count` groups.
Only relevant when `group_count > 0`. Omitting the block is equivalent to
`preset = "balanced"`.

- `preset` `(string: "balanced")` - Named distribution strategy. One of:
  - `balanced` (default) - members spread evenly across all groups (`ceil(entity_count / group_count)` per group)
  - `empty` - groups created with no members
  - `full` - every group holds all entities
- `count` `(int: 0)` - Manual mode: number of groups that receive members. Cannot be combined with `preset`.
- `size` `(int: 0)` - Manual mode: number of members per filled group. Cannot be combined with `preset`.

### Block `policies`

Controls how the `policy_count` policies are distributed as `token_policies`
across entities **and** groups. Only relevant when `policy_count > 0`. Omitting
the block is equivalent to `preset = "balanced"`. The same distribution
parameters are applied to both entities and groups using a single shared
`parsePolicies` result — `count` and `size` control both sets together, not
each set separately.

- `preset` `(string: "balanced")` - Named distribution strategy. One of:
  - `balanced` (default) - policies spread evenly across all entities/groups (`ceil(policy_count / entity_count)` per object)
  - `empty` - no policies are attached regardless of `policy_count`
  - `full` - every entity and group receives all `policy_count` policies
- `count` `(int: 0)` - Manual mode: number of entities/groups that receive policies. Cannot be combined with `preset`.
- `size` `(int: 0)` - Manual mode: number of policies attached to each filled entity/group. Cannot be combined with `preset`.

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

Give each entity multiple aliases (3 per entity), spread evenly:

```hcl
test "identity" "identity_multi_alias" {
  weight = 100
  config {
    workload     = "login"
    entity_count = 1000
    alias_count  = 3000
    login_users  = 100
    aliases {
      preset = "balanced"
    }
  }
}
```

Give aliases only to a specific subset of entities -- 200 entities each get 5 aliases:

```hcl
test "identity" "identity_partial_aliases" {
  weight = 100
  config {
    workload     = "login"
    entity_count = 1000
    alias_count  = 1000
    login_users  = 100
    aliases {
      count = 200
      size  = 5
    }
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

Attach policies to entities and groups -- 10 policies spread evenly across
all 1000 entities, and all 50 groups each receive the balanced policy slice:

```hcl
test "identity" "identity_with_policies" {
  weight = 100
  config {
    workload      = "group_read"
    entity_count  = 1000
    group_count   = 50
    policy_count  = 10
  }
}
```

Attach a fixed number of policies to only some entities and groups -- 5 of
the 10 policies go to 100 entities and 20 groups each:

```hcl
test "identity" "identity_partial_policies" {
  weight = 100
  config {
    workload      = "group_read"
    entity_count  = 1000
    group_count   = 50
    policy_count  = 10
    policies {
      count = 100
      size  = 5
    }
  }
}
```

Give every entity 5 aliases (one per auth mount slot), using `full`:

```hcl
test "identity" "identity_full_aliases" {
  weight = 100
  config {
    workload     = "login"
    entity_count = 1000
    alias_count  = 5        # 5 aliases per entity; 5 userpass mounts are created
    login_users  = 100
    aliases {
      preset = "full"
    }
  }
}
```

Seed a persistent bloat dataset with policies attached to every object:

```hcl
test "identity" "identity_seed" {
  weight = 100
  config {
    # populate always keeps its objects, and the attack phase still runs for
    # the full global `duration` (nothing to skip to) -- keep duration short,
    # e.g. "1s".
    # Note: setup still runs a login-resolution validation for up to
    # login_users (default 100) users when alias_count > 0. This is expected.
    workload      = "populate"
    entity_count  = 10000
    alias_count   = 10000
    group_count   = 500
    policy_count  = 20
    policies {
      preset = "full"
    }
  }
}
```
