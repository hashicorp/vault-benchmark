# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# SCIM performance benchmark — large membership stress config.
#
# Purpose: isolate the cost of group membership at extreme sizes.
# "What if the IdP sends groups with too many memberships?"
#
# HOW TO USE
# ----------
# Step 1: Run OPTION B first (empty baseline) — establishes the floor.
# Step 2: Uncomment OPTION A and comment out OPTION B.
#         Change members_per_group and user_seed_count together across runs:
#           members_per_group = 10,   user_seed_count = 10
#           members_per_group = 50,   user_seed_count = 50
#           members_per_group = 100,  user_seed_count = 100
#           members_per_group = 250,  user_seed_count = 250
#           members_per_group = 500,  user_seed_count = 500
#           members_per_group = 1000, user_seed_count = 1000
# Step 3: Record mean and p99 for each run. The delta vs OPTION B = membership overhead.
# Step 4: Optionally run OPTION C to measure adoption in isolation.
#
# NOTE ON RPS
# -----------
# rps=50 is intentionally conservative. From a remote client the effective
# throughput is limited by network RTT (~110ms to HVD), not Vault capacity.
# The goal here is relative comparison (empty vs N members), not absolute
# throughput — rps=50 gives enough samples for stable p99 without overwhelming
# the connection pool.
#
# WHAT TO RECORD PER RUN
# ----------------------
#   members_per_group | mean | p95 | p99 | successRatio
#   ------------------|------|-----|-----|-------------
#   0 (baseline)      |      |     |     |
#   10                |      |     |     |
#   50                |      |     |     |
#   100               |      |     |     |
#   250               |      |     |     |
#   500               |      |     |     |
#   1000              |      |     |     |
#
# Prerequisites:
#   export VAULT_ADDR="https://<cluster>:8200"
#   export VAULT_TOKEN=<admin token>
#   export VAULT_NAMESPACE=admin
#
# Run:
#   vault-benchmark run -config=test-fixtures/configs/scim_membership.hcl

duration      = "120s"
rps           = 50
report_mode   = "terse"
random_mounts = true
cleanup       = true

# ── OPTION B: empty baseline (run this first) ─────────────────────────────────
#
# Establishes the floor: what does group creation cost with zero members?
# Record mean and p99. Every other run is measured as delta from these numbers.
#
# pool = 50 rps × 120s × 2 = 12 000

# test "scim_groups" "scim_group_create_empty_baseline" {
#   weight = 100
#   config {
#     workload    = "group_create_empty"
#     group_count = 12000
#   }
# }

# ── OPTION A: group_create with N members (comment in, comment out B) ─────────
#
# Change members_per_group and user_seed_count to the same value each run.
# user_seed_count members are created during setup and sampled round-robin —
# so user_seed_count=100 means 100 unique member entities are reused across all
# group POST bodies (you don't need group_count × members_per_group users).
#
test "scim_groups" "scim_group_create_large_membership" {
  weight = 100
  config {
    workload          = "group_create"
    group_count       = 12000
    members_per_group = 100
    user_seed_count   = 100
  }
}

# ── OPTION C: group_adopt in isolation (optional) ─────────────────────────────
#
# Does adoption latency stay flat as the number of adoptable groups grows?
# Vary group_count across runs: 500, 2000, 5000, 9000.
# Compare mean and p99 — if they climb, the adoption lookup is O(n).
#
# test "scim_groups" "scim_group_adopt_isolated" {
#   weight = 100
#   config {
#     workload    = "group_adopt"
#     group_count = 12000
#   }
# }
