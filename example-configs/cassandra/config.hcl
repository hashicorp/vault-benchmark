# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
duration = "1s"
report_mode = "terse"
random_mounts = true


test "cassandra_secret" "cassandra_secret_1" {
    weight = 100
    config {
        db {
            hosts =  "127.0.0.1"
            username = "cassandra"
            password = "cassandra"
            protocol_version = "3"
        }

        role {
            creation_statements = "CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"
        }
    }
}