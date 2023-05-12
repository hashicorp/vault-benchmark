listener "tcp" {
  tls_disable = 1
  address = "[::]:8200"
  cluster_address = "[::]:8201"
}

storage "raft" {
  path = "/vault/file"
  performance_multiplier = "1"
}

disable_mlock = true