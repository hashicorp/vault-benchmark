package testfixtures

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"testing"

	"github.com/hashicorp/vault-benchmark/docker/postgresqldocker"
	// "github.com/hashicorp/vault/helper/testhelpers/etcd"
)

func TestEtcd3Backend(t *testing.T) {
	_, _ = postgresqldocker.PrepareTestContainer(t, "13.4-buster")

}
