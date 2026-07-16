# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# General identity showcase: one run exercising every workload the target
# supports. Kept small and short so it stays a smoke test; the docs carry the
# per-workload examples. NOTE: config keys settle in the Phase 3 reframe.

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
    concurrency  = 10
  }
}

# Log in as seeded entities, validating that aliases resolve correctly.
test "identity" "identity_login" {
  weight = 33
  config {
    workload       = "login"
    entity_count   = 100
    create_users   = true
    create_aliases = true
    concurrency    = 10
  }
}

# Read internal groups by id under load.
test "identity" "identity_group_read" {
  weight = 33
  config {
    workload     = "group_read"
    entity_count = 100
    group_count  = 100
    group_size   = 10
    concurrency  = 10
  }
}
