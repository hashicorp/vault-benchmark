# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# SCIM performance benchmark — Pure 9,000 User Adoption Spike.
#
# Purpose: Simulates an IdP syncing ~9,000 users that already exist as
# unmanaged Vault entities (e.g. from prior SAML/OIDC logins) and adopting them into SCIM.
#
# Math:
#   duration = 300s (5 minutes)
#   rps      = 30
#   Total requests = 30 rps × 300s = 9,000 adoptions (POST /v1/identity/scim/v2/Users)
#   Pre-seeded adoption pool = 10,000 (pre-seeded during setup across 16 parallel workers)

duration      = "300s"
rps           = 30
workers       = 25
report_mode   = "terse"
random_mounts = true
cleanup       = true

test "scim_users" "pure_user_adoption_spike" {
  weight = 100
  config {
    workload   = "user_adopt"
    user_count = 10000
  }
}
