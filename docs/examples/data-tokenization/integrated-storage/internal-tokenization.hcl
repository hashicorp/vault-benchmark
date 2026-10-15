# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

vault_addr = "http://127.0.0.1:8200"
vault_token = "root"
vault_namespace="root"
duration = "30s"

test "transform_tokenization" "tokenization_passport" {
  weight = 100
  config {
    role {
      name = "benchmark-role"
      transformations = [ "passport" ]
    }
    tokenization {
      name          = "passport"
      stores        = ["builtin/internal"]
    }
    input {
      transformation = "passport"
      ttl   = "5s"
      value = "123456789"
    }
  }
}
