package dockertest

// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

// TestIdentity_Docker smoke-tests the identity target against a real Vault by
// running the general showcase fixture (populate + login + group_read blocks) in
// a single benchmark run and asserting it exits cleanly.
func TestIdentity_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "identity.hcl")
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
