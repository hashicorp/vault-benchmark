# Copyright (c) HashiCorp, Inc.
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