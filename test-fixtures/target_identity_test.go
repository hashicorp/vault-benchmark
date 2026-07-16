package dockertest

// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

func TestIdentityGroupRead_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "identity_group_read.hcl")
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestIdentityLogin_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "identity_login.hcl")
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
