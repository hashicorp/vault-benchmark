# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "2s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "jwt_auth" "jwt_test_1" {
    weight = 100
}
