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
        mongodb_config {
            name = "mongo-benchmark-database"
            plugin_name = "mongodb-database-plugin"
            connection_url = "mongodb://{{username}}:{{password}}@127.0.0.1:27017/admin?tls=false"
            write_concern = "{ \"wmode\": \"majority\", \"wtimeout\": 5000 }"
            username = "mdbadmin"
            password = "root"
        }
        role_config {
            db_name = "mongo-benchmark-database"
            creation_statements = "{ \"db\": \"admin\", \"roles\": [{ \"role\": \"readWrite\" }, {\"role\": \"read\", \"db\": \"foo\"}] }"
            default_ttl = "1h"
            max_ttl = "24h"
        }
    }
}
