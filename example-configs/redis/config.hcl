# Basic Benchmark config options
vault_addr = "https://127.0.0.1:8200"
vault_token = "root"
duration = "2s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "redis_secret" "redis_secret_1" {
    weight = 100
    config {
        db_config {
            host = "localhost"
	        db_name = "redis" 
            port = "6379"
            username = "benchmark-user" 
            password = "pass"
            allowed_roles = ["my-*-role"]
            tls = false 
        }

        dynamic_role_config {
            role_name = "my-dynamic-role"
            creation_statements = "[\"+@admin\"]"
            default_ttl = "5m"
            max_ttl = "1h"
        }
    }
}
