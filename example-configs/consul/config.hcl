# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "5s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "consul_secret" "consul_test_1" {
    weight = 100
    config {
        version = "1.7.0"
        consul {
            address = "127.0.0.1:8500"
        }
        role {
            node_identities = [
                "client-1:dc1",
                "client-2:dc1"
            ]
            service_identities = [
                "server-1:dc1",
                "server-2:dc1"
            ]
        }
    }
}
