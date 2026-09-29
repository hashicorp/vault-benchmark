# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# ══════════════════════════════════════════════════════════════════════════════
# GET /Users Filter Performance Under Load
# Task Question: "List GET Users performs well, with different filters"
# ══════════════════════════════════════════════════════════════════════════════
#
# Exercises GET /v1/identity/scim/v2/Users across four distinct filter shapes
# at high query throughput to identify filter scan vs index lookup bottlenecks:
#   1. ""                          — Full scan (no filter, worst-case latency)
#   2. userName eq "..."           — Point lookup by exact userName
#   3. active eq true              — Boolean attribute scan
#   4. meta.lastModified gt "..."  — Time-range scan
#
# seed_user_count pre-creates 5,000 SCIM-owned users during setup (before the
# timed run starts) so every filter shape above has real, findable data to
# query instead of running against an empty namespace. The userName filter
# uses the $SEED_USERNAME token, which Setup() substitutes with the actual
# name of pre-seeded user #0 — a hardcoded literal can never match a
# runID-scoped name and would always return zero results.
#
# Math:
#   duration = 60s
#   rps      = 200
#   workers  = 50
#   Total queries = 12,000 GET requests (~3,000 per filter shape)

duration      = "60s"
rps           = 200
workers       = 50
log_level     = "DEBUG"
report_mode   = "verbose"
random_mounts = true
cleanup       = true

test "scim_users" "filter_perf_users" {
  weight = 100
  config {
    workload        = "user_list"
    seed_user_count = 5000
    filters  = [
      "",
      "userName eq \"$SEED_USERNAME\"",
      "active eq true",
      "meta.lastModified gt \"2020-01-01T00:00:00Z\"",
    ]
  }
}
