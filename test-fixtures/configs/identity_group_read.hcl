# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

duration = "20s"
report_mode = "terse"
random_mounts = true
cleanup = true

test "identity_group_read" "identity_scale_read" {
  weight = 100
  config {
    entity_count = 1000
    group_count = 1000
    group_size = 10
    workload = "group_read"
    create_aliases = true
    userpass_mount = "userpass"
  }
}
