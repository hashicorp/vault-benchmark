# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# General identity showcase: one run exercising every workload the target
# supports. Kept small and short so it stays a smoke test; the docs carry the
# per-workload examples.

duration      = "10s"
report_mode   = "terse"
random_mounts = true
cleanup       = true

# Seed-only: builds an identity dataset, then idles on sys/health.
test "identity" "identity_populate" {
  weight = 34
  config {
    workload     = "populate"
    entity_count = 100
  }
}

# Log in as seeded users, validating that aliases resolve correctly.
test "identity" "identity_login" {
  weight = 33
  config {
    workload     = "login"
    entity_count = 100
    alias_count  = 100
    login_users  = 50
  }
}

# Read internal groups by id under load. An omitted groups block spreads
# entities evenly across groups; shown here explicitly.
test "identity" "identity_group_read" {
  weight = 33
  config {
    workload     = "group_read"
    entity_count = 100
    group_count  = 100
    groups {
      preset = "balanced"
    }
  }
}
