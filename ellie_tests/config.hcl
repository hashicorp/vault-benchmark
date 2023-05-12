# Basic Benchmark config options
vault_addr = "http://127.0.0.1:8200"
vault_token = "hvs.OOl1edFwjZ2apzEdquTNHQlh"
duration = "2s"
report_mode = "terse"
random_mounts = true

# Test selection and options
test "approle_auth"  "approle_test_1" {
    weight = 25
    config {
        role {
            role_name = "test"
	        bind_secret_id = true
            token_ttl = "5m"
            token_num_uses = 5
            token_bound_cidrs = ["1.2.3.0/24", "1.2.4.1/24"]
        }

        secret_id {
            token_bound_cidrs = ["1.2.3.4/32"]
            ttl = "5m"
        }
    }
}

// // test cert

// // test jwt

// // test k8s

// // ldap

// // userpass

test "userpass_auth" "userpass_test1" {
    weight = 25
    config {
        username = "test-user"
        password = "password"
    }
}

test "cassandra_secret" "cassandra_secret1" {
    weight = 25
    config {
        db_connection {
            hosts =  "cassandra"
            username = "cassandra"
            password = "cassandra"
            protocol_version = "3"
        }

        role {
            creation_statements = ["CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"]
        }
    }
}

test "couchbase_secret" "couchbase_test_1" {
    weight = 25
    config {
        db_connection {
            username = "Administrator"
            password = "hudson"
            hosts = "couchbase"
            bucket_name = "dogs"
        }

        role {
                default_ttl = "5m"
                max_ttl = "1h"
        }
    }
}