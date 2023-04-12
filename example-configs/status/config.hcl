# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "10s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "ha_status" "ha_status_test_1" {
    weight = 30
}

test "seal_status" "seal_status_test_1" {
    weight = 30
}

test "metrics" "metrics_test_1" {
    weight = 40
}
