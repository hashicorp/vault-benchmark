# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# SCIM performance benchmark — Pure 9,000 User Creation Spike.
#
# Purpose: Simulates an IdP (e.g. Entra ID / Okta) doing an initial sync
# of ~9,000 new users directly into Vault SCIM.
#
# Math:
#   duration = 300s (5 minutes)
#   rps      = 30
#   Total requests = 30 rps × 300s = 9,000 user creations (POST /v1/identity/scim/v2/Users)
#   Pool size = 12,000 (headroom to ensure every user is unique)

duration      = "300s"
rps           = 30
workers       = 25
report_mode   = "terse"
random_mounts = true
cleanup       = true

test "scim_users" "pure_user_creation_spike" {
  weight = 100
  config {
    workload   = "user_create"
    user_count = 12000
  }
}
