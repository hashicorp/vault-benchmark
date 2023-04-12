# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "10s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "transit_sign" "transit_sign_test_1" {
    weight = 25
    config {
        keys_config {
            name = "test2"
        }
        sign_config {
            name = "test2"
            hash_algorithm = "sha1"
        }
    }
}

test "transit_verify" "transit_verify_test_1" {
    weight = 25
}

test "transit_encrypt" "transit_encrypt_test_1" {
    weight = 25
}

test "transit_decrypt" "transit_decrypt_test_1" {
    weight = 25
}
