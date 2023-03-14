# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "1s"
report_mode = "terse"
random_mounts = true


test "postgresql_secret" "approle_test_1" {
    weight = 100
    config {
        postgresql_db_config {
            connection_url = "postgresql://{{username}}:{{password}}@localhost:5432/postgres"
            username = "username"
            password = "password"
        }

        postgresql_role_config {
            creation_statements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
        }
    }
}