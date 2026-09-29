# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# GET /Groups Filter Performance Under Load
# Task Question: "Validate GET Groups performance, for different types of filters"
# ══════════════════════════════════════════════════════════════════════════════
#
# Exercises GET /v1/identity/scim/v2/Groups across filter shapes:
#   1. ""                                    — Full scan (all groups)
#   2. displayName eq "nonexistent-group"    — Point lookup, guaranteed miss
#   3. displayName eq "..."                  — Point lookup, guaranteed hit
#
# seed_group_count pre-creates 5,000 SCIM-owned groups during setup (before the
# timed run starts) so the full scan and the "hit" filter have real data to
# query instead of running against an empty namespace. The hit filter uses the
# $SEED_GROUPNAME token, which Setup() substitutes with the actual displayName
# of pre-seeded group #0.
#
# Math:
#   duration = 60s
#   rps      = 200
#   workers  = 50
#   Total queries = 12,000 GET requests (~4,000 per filter shape)

duration      = "60s"
rps           = 200
workers       = 50
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_groups" "filter_perf_groups" {
  weight = 100
  config {
    workload         = "group_list"
    seed_group_count = 5000
    filters  = [
      "",
      "displayName eq \"nonexistent-group\"",
      "displayName eq \"$SEED_GROUPNAME\"",
    ]
  }
}
