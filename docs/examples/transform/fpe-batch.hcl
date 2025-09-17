# Example configuration for Transform FPE batch credit card encoding

vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
vault_namespace = "root"
duration = "30s"
cleanup = true

test "transform_fpe" "batch_cc_encode" {
  weight = 100
  config {
    input {
      value = "4111-1111-1111-1111"
      batch_size = 10
    }
  }
}