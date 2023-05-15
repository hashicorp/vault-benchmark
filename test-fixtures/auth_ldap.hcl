# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

config {
    ldap_auth_config {
        url         = "ldap://localhost"
    }
    ldap_test_user_config  {
        username = "alice"
        password = "password"
    }
}