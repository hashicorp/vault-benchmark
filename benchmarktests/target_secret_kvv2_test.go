// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

func TestKVV2Test_ParseConfig(t *testing.T) {
	k := KVV2Test{}

	hclFile, diags := hclparse.NewParser().ParseHCLFile(filepath.Join(FixturePath, "kvv2.hcl"))
	if diags != nil {
		t.Fatalf("err: %v", diags)
	}

	err := k.ParseConfig(hclFile.Body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !k.config.NoStoreMetadata {
		t.Fatal("expected no_store_metadata to be true")
	}
}
