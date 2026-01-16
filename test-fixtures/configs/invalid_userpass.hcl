# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: MPL-2.0

duration      = "2s"
report_mode   = "terse"
random_mounts = true

test "userpass_auth" "userpass_test1" {
    weight = 100
    config {
        username = "test-user"
        password = "password-wrong"
    }
}