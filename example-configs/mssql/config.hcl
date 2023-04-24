# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "10s"
report_mode = "terse"
random_mounts = true


test "mssql_secret" "mssql_test_1" {
    weight = 100
    config {
        db_config {
            connection_url = "sqlserver://{{username}}:{{password}}@localhost:1433"
            username = "username"
            password = "P@SSW0RD"
        }

        role_config {
            creation_statements = "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}'; CREATE USER [{{name}}] FOR LOGIN [{{name}}]; GRANT SELECT ON SCHEMA::dbo TO [{{name}}];"
        }
    }
}
