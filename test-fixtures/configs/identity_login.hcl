# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

duration = "20s"
report_mode = "terse"
random_mounts = true
cleanup = true

test "identity_group_read" "identity_login" {
  weight = 100
  config {
    workload          = "login"
    entity_count      = 1000
    create_users      = true
    create_aliases    = true
    userpass_mount    = "userpass"
    progress_interval = 200
    concurrency       = 10
  }
}
