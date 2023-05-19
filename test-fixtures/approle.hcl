vduration      = "2s"
report_mode   = "terse"
random_mounts = true


test "approle_auth" "approle_test1" {
  weight = 100
  config {
    role {
      role_name         = "test"
      bind_secret_id    = true
      token_ttl         = "10m"
      token_type = "batch"
    }

    secret_id {
      token_bound_cidrs = ["1.2.3.4/32"]
      ttl               = "10m"
    }
  }
}