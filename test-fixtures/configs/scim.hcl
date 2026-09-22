# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# SCIM performance benchmark — local smoke-test config.
#
# This config exercises all 6 SCIM workloads at small scale so you can verify
# the benchmark does the right thing on a local dev cluster before scaling up.
#
# Prerequisites (run once against your cluster):
#   export VAULT_ADDR="http://127.0.0.1:8200"
#   export VAULT_TOKEN=<root or admin token>
#   # Optionally: export VAULT_NAMESPACE=admin
#
# Run:
#   vault-benchmark run -config=test-fixtures/configs/scim.hcl
#
# What each test block does:
#
#   scim_user_create    — POST /scim/v2/Users N times, each with a unique
#                         userName. Measures raw user-creation throughput.
#
#   scim_user_adopt     — POST /scim/v2/Users targeting 50 pre-seeded unmanaged
#                         entities (entity name ≠ alias name, matching real IdP
#                         login behaviour). Each request adopts a different entity.
#
#   scim_user_list      — GET /scim/v2/Users cycling through three filter shapes:
#                         no-filter, userName eq, and meta.lastModified gt.
#
#   scim_group_create   — POST /scim/v2/Groups with 5 SCIM-owned member IDs per
#                         group. Measures group-creation + membership write path.
#
#   scim_group_adopt    — PUT /scim/v2/Groups/<id> adopting 30 pre-seeded
#                         unmanaged groups one at a time.
#
#   scim_group_list     — GET /scim/v2/Groups cycling through two filter shapes.
#
# Weights must sum to 100.

# Sizing: 50 rps × 30 s = 1500 requests total.
# Expected per target = 1500 × (weight / 100):
#   weight=21 → ~315 requests   weight=19 → ~285 requests   weight=10 → ~150 requests
#
# Pool sizes are set to 2× the expected request count so adoption/create pools
# never cycle even with random weight variance.
#
# Formula when scaling further:
#   user_count / group_count >= 2 × rps × duration_seconds × (weight / 100)
#
# NOTE: user_create intentionally has weight=21 (one more than user_adopt=19).
# The reporter attributes results by matching the URL against each target's
# pathPrefix in weight-sorted order (highest weight first), stopping at the first
# match. user_create uses a sentinel suffix (?_w=create) on its URL so the bare
# /Users prefix does not accidentally swallow create results. For this sentinel
# to work reliably, user_create MUST sort before user_adopt — which requires it
# to have a strictly higher weight. The 1-point difference has no measurable
# effect on load distribution at these scales.
duration      = "30s"
rps           = 50
report_mode   = "terse"
# vault-benchmark requires random_mounts = true when cleanup = true.
# SCIM targets ignore random_mounts (they scope everything by runID internally),
# so this flag has no effect on SCIM setup — it just satisfies the framework check.
random_mounts = true
cleanup       = true

# ── User workloads ────────────────────────────────────────────────────────────

# user_create: weight=21 → ~315 requests. Pool of 630 unique userNames (2× headroom).
# Every request creates a genuinely new entity — no name is reused within the run.
# weight=21 (not 20) guarantees user_create sorts before user_adopt in the reporter,
# so the ?_w=create sentinel URL is checked first and does not fall through to the
# bare /Users prefix matcher. See NOTE above.
test "scim_users" "scim_user_create" {
  weight = 21
  config {
    workload   = "user_create"
    user_count = 630
  }
}

# user_adopt: weight=19 → ~285 requests. Pool of 570 pre-seeded unmanaged entities (2× headroom).
# Entity name ≠ alias name, mirroring real IdP login-created entities.
# Every request adopts a DIFFERENT entity — pool never cycles.
test "scim_users" "scim_user_adopt" {
  weight = 19
  config {
    workload   = "user_adopt"
    user_count = 570
  }
}

# user_list: weight=10 → ~150 requests. Three filter shapes round-robined (~50 each).
# An empty filter string means "no filter" (returns all SCIM-owned users).
test "scim_users" "scim_user_list" {
  weight = 10
  config {
    workload = "user_list"
    filters  = [
      "",
      "meta.lastModified gt \"2020-01-01T00:00:00Z\"",
      "active eq true",
    ]
  }
}

# ── Group workloads ───────────────────────────────────────────────────────────

# group_create (with members): weight=20 → ~300 requests.
# Pool of 600 unique displayNames (2× headroom).
# Each POST body includes 5 SCIM-owned member entity IDs.
# user_seed_count=5 seeds 5 SCIM-owned users during setup; members are
# sampled round-robin from those 5 for every group POST.
# To test the "too many memberships" case, raise members_per_group and
# user_seed_count together (user_seed_count must be >= members_per_group).
test "scim_groups" "scim_group_create" {
  weight = 20
  config {
    workload          = "group_create"
    group_count       = 600
    members_per_group = 5
    user_seed_count   = 5
  }
}

# group_adopt: weight=10 → ~150 requests. Pool of 300 pre-seeded unmanaged groups (2× headroom).
# Every PUT adopts a DIFFERENT group — pool never cycles.
test "scim_groups" "scim_group_adopt" {
  weight = 10
  config {
    workload    = "group_adopt"
    group_count = 300
  }
}

# group_list: weight=10 → ~150 requests. Two filter shapes round-robined (~75 each).
# Filters are URL-encoded automatically — spaces and quotes are safe to write here.
test "scim_groups" "scim_group_list" {
  weight = 10
  config {
    workload = "group_list"
    filters  = [
      "",
      "displayName eq \"nonexistent-group\"",
    ]
  }
}

# group_create_empty (no members): weight=10 → ~150 requests.
# Isolates the raw group-creation path from the member-validation path.
# Compare latency with scim_group_create above to see membership overhead.
# Uses workload="group_create_empty" — a dedicated workload constant — so the
# reporter can attribute results correctly (it uses a distinct ?_w=empty sentinel
# URL that is not confused with group_create's ?_w=create sentinel).
test "scim_groups" "scim_group_create_empty" {
  weight = 10
  config {
    workload    = "group_create_empty"
    group_count = 300
  }
}
