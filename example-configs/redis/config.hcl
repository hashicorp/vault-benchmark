# Basic Benchmark config options
vault_addr    = "https://127.0.0.1:8200"
vault_token   = "root"
duration      = "2s"
report_mode   = "terse"
random_mounts = true


test "redis_dynamic_secret" "redis_dynamic_secret_1" {
  weight = 40
  config {
    db {
      host          = "localhost"
      name          = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "default"
      password      = "pass"
      tls           = false
    }

    role {
      name                = "my-dynamic-role"
      creation_statements = "[\"+@admin\"]"
      db_name             = "redis"
      default_ttl         = "5m"
      max_ttl             = "1h"
    }
  }
}

test "redis_static_secret" "redis_static_secret_1" {
  weight = 60
  config {
    db {
      host          = "localhost"
      name          = "redis"
      port          = "6379"
      allowed_roles = ["my-*-role"]
      username      = "default"
      password      = "pass"
      tls           = false
    }

    role {
      name            = "my-s-role"
      db_name         = "redis"
      rotation_period = "5m"
      username        = "my-static-role"
    }
  }
}

