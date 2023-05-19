vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
vault_namespace="root"
duration = "30s"

test "pki_issue" "pki_issue" {
    weight = 100
    config {
        setup_delay="2s"
        root_ca {
            common_name = "benchmark.test Root Authority"
            key_type = "ec"
            key_bits = "384"
        }
        intermediate_csr {
            common_name = "benchmark.test Intermediate Authority"
            key_type = "ec"
            key_bits = "384"
        }
        role {
            ttl = "10s"
            no_store = false
            generate_lease = true
            key_type = "ec"
            key_bits = "384"
        }
    }
}
