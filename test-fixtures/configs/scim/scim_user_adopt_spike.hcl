# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# User Adoption Spike Test
# Task Question: "What if those user creations are adoptions?"
# ══════════════════════════════════════════════════════════════════════════════
#
# Simulates an IdP pushing a high-rate spike of user adoptions.
# Setup seeds unmanaged entities with aliases. During the attack, each POST
# targets an unmanaged entity alias, forcing Vault to execute the adoption path.
#
# Run at step-up RPS to compare directly against creation spike:
#   Run 1: rps = 100, workers = 100  (Moderate spike)
#   Run 2: rps = 250, workers = 250  (Heavy spike)
#   Run 3: rps = 500, workers = 500  (Extreme spike / breaking limit)
#
# user_count carries 25% headroom over the nominal rps x duration request count
# (100 x 60s = 6,000) so a timing overshoot can't wrap the pool index back onto
# an already-adopted userName, which would surface as a false 409 conflict
# instead of a fresh adoption.

duration      = "60s"
rps           = 100
workers       = 100
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_users" "spike_user_adopt" {
  weight = 100
  config {
    workload   = "user_adopt"
    user_count = 7500
  }
}
