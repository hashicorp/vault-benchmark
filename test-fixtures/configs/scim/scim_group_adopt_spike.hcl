# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# Group Adoption Spike Test
# Task Question: "What if those group creations are adoptions?"
# ══════════════════════════════════════════════════════════════════════════════
#
# Simulates an IdP pushing a high-rate spike of group adoptions.
# Setup seeds unmanaged internal Vault groups. During the attack, each PUT
# adopts a pre-existing group into SCIM.
#
# Run at step-up RPS to compare directly against creation spike:
#   Run 1: rps = 100, workers = 100  (Moderate spike)
#   Run 2: rps = 250, workers = 250  (Heavy spike)
#   Run 3: rps = 500, workers = 500  (Extreme spike / breaking limit)
#
# group_count carries 25% headroom over the nominal rps x duration request count
# (100 x 60s = 6,000) so a timing overshoot can't wrap the pool index back onto
# an already-adopted group, which would surface as a false 403/uniqueness error
# instead of a fresh adoption.

duration      = "60s"
rps           = 100
workers       = 100
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_groups" "spike_group_adopt" {
  weight = 100
  config {
    workload    = "group_adopt"
    group_count = 7500
  }
}
