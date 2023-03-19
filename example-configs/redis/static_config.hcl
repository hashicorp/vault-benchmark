# Basic Benchmark config options
vault_addr    = "https://127.0.0.1:8200"
vault_token   = "root"
duration      = "2s"
report_mode   = "terse"
random_mounts = true

# Test selection and options
test "redis_secret" "redis_secret_1" {
  weight = 100
  config {
    db_config {
      host          = "localhost"
      db_name       = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "user"
      password      = "pass"
      tls           = false
    }

    static_role_config {
      role_name       = "my-s-role"
      rotation_period = "5m"
      username        = "my-static-role"
    }
  }
}

