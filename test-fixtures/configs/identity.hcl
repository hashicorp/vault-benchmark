# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

# General identity showcase: one run exercising every workload the target
# supports, including the aliases and policies allocation blocks.
# Kept small and short so it stays a smoke test; the docs carry the
# per-workload examples.

duration      = "10s"
report_mode   = "terse"
random_mounts = true
cleanup       = true

# Seed-only: builds an identity dataset, then idles on sys/health.
test "identity" "identity_populate" {
  weight = 25
  config {
    workload     = "populate"
    entity_count = 100
  }
}

# Log in as seeded users, validating that aliases resolve correctly.
test "identity" "identity_login" {
  weight = 25
  config {
    workload     = "login"
    entity_count = 100
    alias_count  = 100
    login_users  = 50
  }
}

# Login with multiple aliases per entity: 3 aliases spread evenly across
# all entities via the aliases block.
test "identity" "identity_login_multi_alias" {
  weight = 25
  config {
    workload     = "login"
    entity_count = 100
    alias_count  = 300
    login_users  = 50
    aliases {
      preset = "balanced"
    }
  }
}

# Read internal groups by id under load. Policies are spread evenly across
# all entities and groups via the policies block.
test "identity" "identity_group_read" {
  weight = 25
  config {
    workload      = "group_read"
    entity_count  = 100
    group_count   = 10
    policy_count  = 5
    groups {
      preset = "balanced"
    }
    policies {
      preset = "balanced"
    }
  }
}
