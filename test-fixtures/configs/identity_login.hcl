# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

duration = "20s"
report_mode = "terse"
random_mounts = true
cleanup = true

test "identity" "identity_login" {
  weight = 100
  config {
    entity_count = 1000
    name_prefix = "entity"
    progress_interval = 200
    workload = "login"
    create_users = true
    create_aliases = true
    userpass_mount = "userpass"
  }
}
