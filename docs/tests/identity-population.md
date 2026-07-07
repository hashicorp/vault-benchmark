# Identity Population Benchmark (`identity_population`)

This benchmark creates a set of Vault Identity entities during the setup phase, and can optionally make those entities loginable so the attack phase drives real userpass logins that resolve to the generated entities.

Use this target to seed an identity dataset, measure identity entity creation performance, or generate login traffic that exercises Vault's identity resolution end to end.

## Test Parameters

### Configuration `config`

- `entity_count` `(int: 10000)` - number of Identity entities to create during setup.
- `name_prefix` `(string: "seed-entity")` - prefix used for generated entity names. Entity names are created as `<name_prefix>-000001`, `<name_prefix>-000002`, etc.
- `progress_interval` `(int: 1000)` - how often to log setup progress during entity creation.
- `link_userpass_auth` `(bool: false)` - make the generated entities loginable. When enabled, setup creates one userpass user and one entity alias per entity (both named after the entity), and the attack phase logs in as randomly selected users so traffic resolves to the generated entities. When disabled, this target only populates entities.
- `userpass_mount` `(string: "userpass")` - userpass auth mount used for created users and aliases. Enabled automatically if it does not already exist.

## Example Configuration

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

## Behavior

This target has two modes, selected by `link_userpass_auth`:

**Setup-only population (`link_userpass_auth = false`, default)**

- Seeds entities and nothing else — it is a setup-time population workflow.
- Uses Vault's built-in Identity API at `identity/entity/name/<name>`, reading each entity back to capture its generated ID.
- Because pure population has no meaningful attack of its own, the attack phase issues a harmless `/v1/sys/health` GET as a no-workload placeholder (the benchmark runner always requires a target). Pair this target with another target if you want real workload alongside the seeded data.

**Loginable identities (`link_userpass_auth = true`)**

- In addition to seeding entities, setup enables the `userpass_mount` (if needed), creates a userpass user per entity, and creates the matching `identity/entity-alias` so logins resolve to the correct entity.
- Setup performs a single smoke login (see [Setup validation](#setup-validation) below) and fails fast on a mismatch.
- The attack phase logs in as randomly selected generated users, so benchmark traffic exercises Vault identity resolution end to end.

**Both modes**

- Cleanup is intentionally deferred in this MVP implementation; the target does not remove created entities automatically.

## Setup validation

When `link_userpass_auth = true`, setup performs a single login against the first generated user and confirms it resolves to that user's expected entity ID, failing fast on a mismatch. This compares against the expected ID because a bare userpass login always returns some entity ID (Vault auto-creates one), so only an expected-vs-actual comparison is meaningful.

- **Purpose:** verify that alias mapping is wired correctly — that a userpass login resolves to the entity it was linked to.
- **Not:** exhaustively validate every generated user. Setup performs one representative login as a fast correctness check, not a per-user audit. Broad login coverage is the job of the attack phase.

## Notes

- Because Identity is a Vault built-in path, this target does not create or manage a secret mount.
- Creating the userpass user and the entity alias are implementation details of making an entity loginable, so they are driven by the single `link_userpass_auth` flag rather than separate options.
- This target owns the full identity-auth workflow (population, linking, login traffic, and validation) in one place, so it does not need to be paired with a separate userpass target.
