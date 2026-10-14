# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: MPL-2.0

vault_addr  = "http://127.0.0.1:8200"
vault_token = "root"
duration    = "30s"

# FPE benchmark with a generated tweak.
# Vault generates and returns a new tweak with each encode response;
# no tweak needs to be provided on the request.
test "transform_fpe" "fpe_generated_tweak_ff1" {
  weight = 100
  config {
    role {
      name            = "benchmark-role"
      transformations = ["ccn-fpe"]
    }
    fpe {
      name          = "ccn-fpe"
      template      = "builtin/creditcardnumber"
      tweak_source  = "generated"
      allowed_roles = ["benchmark-role"]
      max_tweak_len = 10
    }
    input {
      transformation = "ccn-fpe"
      value          = "1111-1111-1111-1111"
    }
  }
}