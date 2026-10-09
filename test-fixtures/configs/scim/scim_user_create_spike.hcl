# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# User Creation Spike Test
# Task Question: "What happens if an IdP sends a spike of user creations?"
# ══════════════════════════════════════════════════════════════════════════════
#
# Simulates an IdP pushing a high-rate spike of brand new user creations.
# Every POST hits POST /v1/identity/scim/v2/Users with a unique userName.
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

test "scim_users" "spike_user_create" {
  weight = 100
  config {
    workload   = "user_create"
    user_count = 35000
  }
}
