# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# Group Creation Spike Test
# Task Question: "What if the IdP sends a spike of group creations?"
# ══════════════════════════════════════════════════════════════════════════════
#
# Simulates an IdP pushing a high-rate spike of new group creations.
# Each group is created with 50 SCIM members to reflect realistic enterprise groups.
#
# Run at step-up RPS to observe queueing and find the saturation point:
#   Run 1: rps = 100, workers = 100  (Moderate spike)
#   Run 2: rps = 250, workers = 250  (Heavy spike)
#   Run 3: rps = 500, workers = 500  (Extreme spike / breaking limit)

duration      = "60s"
rps           = 100
workers       = 100
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_groups" "spike_group_create" {
  weight = 100
  config {
    workload          = "group_create"
    group_count       = 35000
    members_per_group = 50
    user_seed_count   = 100
  }
}
