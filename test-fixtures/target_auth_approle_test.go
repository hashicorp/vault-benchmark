package dockertest

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

func TestApprole_Auth_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "approle.hcl")
	defer benchmarkCleanup()

	if exitCode == 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestApprole_Auth_Failed_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "invalid_token", "approle.hcl")
	defer benchmarkCleanup()

	if exitCode != 1 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestApprole_Invalid_Config_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "invalid_approle.hcl")
	defer benchmarkCleanup()

	if exitCode != 1 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
