package dockertest

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault-benchmark/helper/dockertest"
)

func TestApprole_Auth_Docker(t *testing.T) {
	t.Parallel()

	// Create Network
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		fmt.Errorf("error generating uuid for network name: %w", err)
	}

	networkName := fmt.Sprintf("vault-benchmark-%v", uuid)

	networkCleanup := dockertest.CreateNetwork(t, networkName)
	defer networkCleanup()

	// Create Vault Container
	vaultCleanup, containerName := dockertest.CreateVaultContainer(t, networkName)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http:/%s:8200", containerName)
	exitCode := dockertest.CreateVaultBenchmarkContainer(t, networkName, vaultAddr, "root")

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestApprole_Auth_Failed_Docker(t *testing.T) {
	t.Parallel()

	// Create Network
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		fmt.Errorf("error generating uuid for network name: %w", err)
	}

	networkName := fmt.Sprintf("vault-benchmark-%v", uuid)

	networkCleanup := dockertest.CreateNetwork(t, networkName)
	defer networkCleanup()

	// Create Vault Container
	vaultCleanup, containerName := dockertest.CreateVaultContainer(t, networkName)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http:/%s:8200", containerName)
	exitCode := dockertest.CreateVaultBenchmarkContainer(t, networkName, vaultAddr, "invalid_token")

	if exitCode == 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
