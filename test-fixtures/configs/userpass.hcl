duration      = "2s"
report_mode   = "terse"
random_mounts = true

test "userpass_auth" "userpass_test1" {
    weight = 100
    config {
        username = "test-user"
        password = "password"
        token_bound_cidrs = ["1.2.3.4/32"]
        token_no_default_policy = true
        token_num_uses = 500
        token_period = "3m"
    }
}