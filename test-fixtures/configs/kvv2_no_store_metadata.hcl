# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: MPL-2.0

duration      = "2s"
report_mode   = "terse"
random_mounts = true

test "kvv2_write" "kvv2_write_test" {
    weight = 50
    config {
        numkvs = 10
        no_store_metadata = true
    }
}

test "kvv2_read" "kvv2_read_test" {
    weight = 50
    config {
        numkvs = 10
        no_store_metadata = true
    }
}
