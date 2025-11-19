# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# setup to match the tutorial provided here: https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service/tokenization?productSlug=vault&tutorialSlug=adp&tutorialSlug=tokenization&variants=vault-deploy%3Aenterprise#setup-external-token-storage

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
      stores        = ["postgres"]
    }
    store {
      name                     = "postgres"
      type                     = "sql"
      driver                   = "postgres"
      connection_string        = "postgresql://root:rootpassword@127.0.0.1:5432/root?sslmode=disable"
      username                 = "root"
      password                 = "rootpassword"
      supported_transformations = ["tokenization"]
    }
    store_schema {
      name     = "postgres"
      username = "root"
      password = "rootpassword"
    }
    input {
      transformation = "passport"
      ttl   = "2m"
      value = "123456789"
    }
  }
}
