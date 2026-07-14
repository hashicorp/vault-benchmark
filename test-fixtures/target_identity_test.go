package dockertest

// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

// TestIdentityGroupRead_Docker runs the create_aliases=true fixture; exit 0
// means setup and the sampled login-resolution validation passed against Vault.
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

// TestIdentityPopulation_Docker runs the link_auth=true fixture; exit 0 means
// setup and the sampled login-resolution validation passed against Vault.
func TestIdentityPopulation_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "identity_population.hcl")
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
