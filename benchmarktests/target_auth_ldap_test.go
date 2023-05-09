// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

const (
	FixturePath = "../test-fixtures"
)

func TestLDAPAuthTest_ParseConfig(t *testing.T) {
	tAuth := LDAPAuth{}

	hclFile, diags := hclparse.NewParser().ParseHCLFile(filepath.Join(FixturePath, "auth_ldap.hcl"))
	if diags != nil {
		t.Fatalf("err: %v", diags)
	}

	err := tAuth.ParseConfig(hclFile.Body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}
