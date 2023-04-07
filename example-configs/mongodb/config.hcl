# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "10s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "mongodb_secret" "mongodb_test_1" {
    weight = 100
    config {
        db_config {
            name = "mongo-benchmark-database"
            connection_url = "mongodb://{{username}}:{{password}}@127.0.0.1:27017/admin?tls=false"
        }
        role_config {
            db_name = "mongo-benchmark-database"
        }
    }
}
