# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "1s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "rabbitmq_secret" "rabbit_test_1" {
    weight = 100
    config {
        rabbitmq_config {
            connection_uri = "http://localhost:15672"
            username = "guest"
            password = "guest"
        }
        role_config {
            vhosts = "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}"
        }
    }
}
