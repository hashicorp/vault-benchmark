# Example configuration for Transform FPE single credit card encoding

vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
vault_namespace = "root"
duration = "30s"
cleanup = true

test "transform_fpe" "single_cc_encode" {
  weight = 100
  config {
    input {
      value = "4111-1111-1111-1111"
    }
  }
}