// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

func TestTransitSecret_ParseConfig_BatchInput(t *testing.T) {
	const src = `
config {
  keys {
    name = "orders"
    type = "aes256-gcm96"
  }
  encrypt {
    name = "orders"
    batch_input = [
      { plaintext = "YQ==" },
      { plaintext = "Yg==" },
    ]
  }
  decrypt {
    name = "orders"
    batch_input = [
      { ciphertext = "vault:v1:abc" },
    ]
  }
  sign {
    name = "orders"
    batch_input = [
      { input = "YQ==" },
    ]
  }
  verify {
    name = "orders"
    batch_input = [
      { input = "YQ==", signature = "vault:v1:sig" },
    ]
  }
}
`
	file, diags := hclparse.NewParser().ParseHCL([]byte(src), "transit.hcl")
	if diags.HasErrors() {
		t.Fatalf("parse: %v", diags)
	}

	target := &TransitSecret{}
	if err := target.ParseConfig(file.Body); err != nil {
		t.Fatal(err)
	}

	enc := target.config.TransitEncryptConfig.BatchInput
	if len(enc) != 2 || enc[0]["plaintext"] != "YQ==" || enc[1]["plaintext"] != "Yg==" {
		t.Fatalf("encrypt batch_input = %#v", enc)
	}
	dec := target.config.TransitDecryptConfig.BatchInput
	if len(dec) != 1 || dec[0]["ciphertext"] != "vault:v1:abc" {
		t.Fatalf("decrypt batch_input = %#v", dec)
	}
	sign := target.config.TransitSignConfig.BatchInput
	if len(sign) != 1 || sign[0]["input"] != "YQ==" {
		t.Fatalf("sign batch_input = %#v", sign)
	}
	verify := target.config.TransitVerifyConfig.BatchInput
	if len(verify) != 1 || verify[0]["input"] != "YQ==" || verify[0]["signature"] != "vault:v1:sig" {
		t.Fatalf("verify batch_input = %#v", verify)
	}

	encoded, err := structToMap(target.config.TransitEncryptConfig)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(encoded["batch_input"])
	if err != nil {
		t.Fatal(err)
	}
	const want = `[{"plaintext":"YQ=="},{"plaintext":"Yg=="}]`
	if string(body) != want {
		t.Fatalf("request batch_input = %s, want %s", body, want)
	}
}
