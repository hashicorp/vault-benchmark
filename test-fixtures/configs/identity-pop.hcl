vault_addr = "http://127.0.0.1:8200"
vault_token = "root"

duration = "1s"
workers = 1
rps = 1
random_mounts = false
cleanup = false

test "identity_population" "test1" {
  weight = 100
  config {
    entity_count = 10000
    name_prefix = "seed-entity"
    progress_interval = 1000
  }
}
