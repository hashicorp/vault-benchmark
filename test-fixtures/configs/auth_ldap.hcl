# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: MPL-2.0

config {
    auth {
        url         = "ldap://localhost"
        bindpass    = "admin"
    }
    test_user  {
        username = "alice"
        password = "password"
    }
}