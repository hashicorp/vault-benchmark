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
    weight = 10
    config {
        db_connection {
            username = "Administrator"
            password = "password"
            hosts = "couchbase"
            bucket_name = "buckets"
        }

        role {
                default_ttl = "5m"
                max_ttl = "1h"
        }
    }
}

// elastic search

test "kvv2_read" "kvv2_read_test" {
    weight = 5
    config {
        numkvs = 100
    }
}

test "kvv2_write" "kvv2_write_test" {
    weight = 7
    config {
        numkvs = 10
        kvsize = 1000
    }
}

// mongo

// mssql

// pki issue

// pki sign

// postgres

// rabbit

// redis dynamic

// redis static

// ssh issue

// ssh sign

// transform tokenization

// transit

test "ha_status" "ha_status_test_1" {
    weight = 1
}

test "seal_status" "seal_status_test_1" {
    weight = 1
}

test "metrics" "metrics_test_1" {
    weight = 1
}
