# Identity Population Benchmark ('identity_population')

This benchmark creates a static set of Vault Identity entities during the setup phase.

This target is primarily useful for seeding an identity dataset before running other benchmarks, or for measuring Vault identity entity creation performance in a controlled way. The attack/cleanup phases are intentionally trivial in this MVP.

## Test Parameters

### Configuration `config`

- `entity_count` `(int: 10000)` - number of Identity entities to create during setup.
- `name_prefix` `(string: "seed-entity")` - prefix used for generated entity names. Entity names are created as `<name_prefix>-000001`, `<name_prefix>-000002`, etc.
- `progress_interval` `(int: 1000)` - how often to log setup progress during entity creation.
- `create_aliases` `(bool: true)` - create one entity alias per generated entity.
- `userpass_mount` `(string: "userpass")` - userpass auth mount used to resolve the alias mount accessor.

## Example Configuration

```hcl
test "identity_population" "identity_population_test" {
  weight = 10
  config {
    entity_count      = 5000
    name_prefix       = "scale-entity"
    progress_interval = 500
    create_aliases    = true
    userpass_mount    = "userpass"
  }
}
```

## Behavior

- Uses Vault's built-in Identity API at `identity/entity/name/<name>`.
- Creates entities by name in the setup phase and reads each entity back to capture its generated ID.
- Optionally creates `identity/entity-alias` entries and links alias name to generated entity ID in-memory for later validation.
- The attack phase uses a minimal `/v1/sys/health` GET target so the benchmark runner can execute normally.
- Cleanup is intentionally deferred in this MVP implementation; the target does not remove created entities automatically.

## Notes

- Because Identity is a Vault built-in path, this target does not create or manage a mount.
- When `create_aliases = true`, the target will use the configured `userpass_mount` and enable it if it does not already exist.
- This target does not perform alias-to-entity verification checks yet; it only stores linkages for later checks.
- If you want to test pure identity-entity population without later workload, set a small duration and a low weight for this target in the overall benchmark config.
