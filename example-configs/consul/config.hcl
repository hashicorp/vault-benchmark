# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "10s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "consul_secret" "consul_test_1" {
    weight = 100
    config {
        consul_config {
            address = "127.0.0.1:8500"
            token  = "8b9efdab-cc10-1a5b-2e66-d2833fd5f152"
            version = "1.8.0"
        }
        role_config {
            node_identities = [
                "client-1:dc1",
                "client-2:dc1"
            ]
        }
    }
}
