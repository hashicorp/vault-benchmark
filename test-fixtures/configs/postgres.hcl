# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

duration      = "2s"
report_mode   = "terse"
random_mounts = true

test "postgresql_secret" "postgres_test_1" {
    weight = 100
    config {
        db_connection {
            connection_url = "postgresql://{{username}}:{{password}}@<container_addr>:5432/postgres"
            username = "username"
            password = "password"
        }

        role {
            creation_statements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        }
    }
}