# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# SCIM performance benchmark — scale-up config.
#
# Use this config after the smoke test (scim.hcl) passes on a local cluster.
# Target: a real cluster (dev-enterprise or HVD) where you want to find the
# throughput ceiling and p99 behaviour under realistic IdP spike loads.
#
# Design intent:
#   - Aligned with product expectation of ~9000 users from a customer IdP.
#   - Pools are sized to 2× the expected request count so no name is reused
#     within a single run (no cache hits, no 409 collisions).
#   - Run multiple times at increasing rps to find the knee of the curve:
#       rps=100  duration=120s → 12 000 requests (good baseline)
#       rps=200  duration=120s → 24 000 requests (moderate spike)
#       rps=500  duration=120s → 60 000 requests (large spike)
#   - Keep duration=120s so each workload gets enough samples for stable p99.
#
# Prerequisites:
#   export VAULT_ADDR="https://<cluster>:8200"
#   export VAULT_TOKEN=<admin token>
#   export VAULT_NAMESPACE=admin   # if targeting the admin namespace
#
# Run:
#   vault-benchmark run -config=test-fixtures/configs/scim/scim_scale.hcl
#
# Sizing formula (adjust rps and duration together):
#   pool_size = 2 × rps × duration_seconds × (weight / 100)
#
# At rps=200, duration=120s:
#   weight=21 → ~5 040 requests → pool 10 080
#   weight=19 → ~4 560 requests → pool  9 120
#   weight=20 → ~4 800 requests → pool  9 600
#   weight=10 → ~2 400 requests → pool  4 800
#
# NOTE: user_create has weight=21 (vs user_adopt=19) so the ?_w=create sentinel
# URL is always checked first by the reporter. See scim.hcl for full explanation.

duration      = "1400s"
rps           = 30
workers       = 25
report_mode   = "terse"
random_mounts = true
cleanup       = true

# ── User workloads (~5,000–6,000 requests each) ──────────────────────────────

# user_create: 30 rps × 1400 s × 0.15 = 6 300 requests. Pool = 10 000.
# Simulates an IdP pushing a spike of new user creations.
# Every POST hits a unique userName — no entity is created twice.
test "scim_users" "scim_user_create" {
  weight = 15
  config {
    workload   = "user_create"
    user_count = 10000
  }
}

# user_adopt: 30 rps × 1400 s × 0.14 = 5 880 requests. Pre-seeded pool = 6 500.
# Simulates an IdP pushing adoption of existing login-created users.
# Each request targets a DIFFERENT pre-seeded entity (entity name ≠ alias name).
test "scim_users" "scim_user_adopt" {
  weight = 14
  config {
    workload   = "user_adopt"
    user_count = 6500
  }
}

# user_list: 30 rps × 1400 s × 0.14 = 5 880 requests.
# Cycles through four filter shapes to exercise different list code paths:
#   ""                          — no filter, full scan (worst case)
#   userName eq "..."           — point lookup by userName
#   active eq true              — boolean attribute scan
#   meta.lastModified gt "..."  — time-range scan
test "scim_users" "scim_user_list" {
  weight = 14
  config {
    workload = "user_list"
    filters  = [
      "",
      "userName eq \"bench-create-user-x@example.com\"",
      "active eq true",
      "meta.lastModified gt \"2020-01-01T00:00:00Z\"",
    ]
  }
}

# ── Group workloads (~5,000–6,000 requests each) ──────────────────────────────

# group_create (with members): 30 rps × 1400 s × 0.15 = 6 300 requests. Pool = 10 000.
# members_per_group=50 / user_seed_count=100 exercises realistic group sizes.
test "scim_groups" "scim_group_create" {
  weight = 15
  config {
    workload          = "group_create"
    group_count       = 10000
    members_per_group = 50
    user_seed_count   = 100
  }
}

# group_adopt: 30 rps × 1400 s × 0.14 = 5 880 requests. Pre-seeded pool = 6 500.
# Simulates an IdP adopting existing Vault groups.
# Every PUT targets a DIFFERENT pre-seeded group.
test "scim_groups" "scim_group_adopt" {
  weight = 14
  config {
    workload    = "group_adopt"
    group_count = 6500
  }
}

# group_list: 30 rps × 1400 s × 0.14 = 5 880 requests.
# Exercises both full-scan and filtered list code paths.
test "scim_groups" "scim_group_list" {
  weight = 14
  config {
    workload = "group_list"
    filters  = [
      "",
      "displayName eq \"nonexistent-group\"",
    ]
  }
}

# group_create_empty: 30 rps × 1400 s × 0.14 = 5 880 requests. Pool = 10 000.
# Baseline: group creation with no members. Compare p50/p99 with scim_group_create
# above to isolate the per-member overhead at members_per_group=50.
test "scim_groups" "scim_group_create_empty" {
  weight = 14
  config {
    workload    = "group_create_empty"
    group_count = 10000
  }
}
