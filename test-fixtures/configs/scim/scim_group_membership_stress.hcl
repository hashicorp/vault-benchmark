# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# Extreme Group Membership Payload Stress Test
# Task Question: "What if the IdP sends groups with too many memberships?"
# ══════════════════════════════════════════════════════════════════════════════
#
# Isolates the exact latency and write cost of group membership payloads.
#
# user_seed_count is set to 3x members_per_group (not 1x): the member-selection
# window rotates through the seed pool per group
# (offset = poolIdx * members_per_group mod user_seed_count), so with equal
# counts every group would get the exact same members_per_group members. 3x
# headroom gives 3 distinct rotating membership sets instead of one, without
# materially changing the per-request payload size being measured.
#
# HOW TO RUN THE STEP-UP TEST:
# 1. Run Baseline (0 members) — establishes the floor latency:
#      Change members_per_group = 0, user_seed_count = 1
# 2. Increment membership sizes across subsequent runs (user_seed_count = 3x):
#      members_per_group = 50,    user_seed_count = 150
#      members_per_group = 100,   user_seed_count = 300
#      members_per_group = 250,   user_seed_count = 750
#      members_per_group = 500,   user_seed_count = 1500
#      members_per_group = 1000,  user_seed_count = 3000
#      members_per_group = 2500,  user_seed_count = 7500  (Extreme stress)
# 3. Compare mean and p99 vs the 0-member baseline to isolate membership cost.

duration      = "60s"
rps           = 50
workers       = 25
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_groups" "stress_large_membership" {
  weight = 100
  config {
    workload          = "group_create"
    group_count       = 5000
    members_per_group = 100
    user_seed_count   = 300
  }
}
