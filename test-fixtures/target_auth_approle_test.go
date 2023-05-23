package dockertest

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
)

func TestApprole_Auth_Docker(t *testing.T) {
	// Create Network
	networkName := "vault-benchmark"

	networkCleanup := dockertest.CreateNetwork(t, networkName)
	defer networkCleanup()

	// Create Vault Container
	vaultCleanup, containerName := dockertest.CreateVaultContainer(t, networkName)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http:/%s:8200", containerName)
	benchmarkCleanup := dockertest.CreateVaultBenchmarkContainer(t, networkName, vaultAddr, "root")
	defer benchmarkCleanup()
}
