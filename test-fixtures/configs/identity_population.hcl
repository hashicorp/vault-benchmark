# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

duration = "20s"
report_mode = "terse"
random_mounts = true
cleanup = true

test "identity_population" "identity_population_login" {
  weight = 100
  config {
    entity_count = 1000
    name_prefix = "seed-entity"
    progress_interval = 200
    link_userpass_auth = true
    userpass_mount = "userpass"
  }
}
