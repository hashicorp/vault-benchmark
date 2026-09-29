# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# Maximum User Scale Limit Test (Pushing past 9,000 to 12,000+ users)
# Task Question: "Max users expected from IdPs is ~9000, test the limit"
# ══════════════════════════════════════════════════════════════════════════════
#
# Simulates a continuous, sustained IdP sync stream creating > 10,000 unique users.
# Evaluates whether Vault memory, Raft log, or identity store degrade as total
# user count surpasses 9,000.
#
# Math:
#   duration = 400s (~6.6 minutes)
#   rps      = 30
#   workers  = 25
#   Total unique users created = 30 rps × 400s = 12,000 users

duration      = "400s"
rps           = 30
workers       = 25
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_users" "scale_user_limit_past_9k" {
  weight = 100
  config {
    workload   = "user_create"
    user_count = 15000
  }
}
