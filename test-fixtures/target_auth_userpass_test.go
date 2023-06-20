package dockertest

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

func TestUserpass_Auth_Docker(t *testing.T) {
	t.Parallel()

	// Create Network
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal("error generating uuid for network name: %w", err)
	}

	networkName := fmt.Sprintf("vault-benchmark-%v", uuid)

	networkCleanup := dockertest.CreateNetwork(t, networkName)
	defer networkCleanup()

	// Create Vault Container
	vaultCleanup, containerName := dockertest.CreateVaultContainer(t, networkName)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerName)
	_, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, networkName, vaultAddr, "root", "userpass.hcl")

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestUserpass_Auth_Failed_Docker(t *testing.T) {
	t.Parallel()

	// Create Network
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal("error generating uuid for network name: %w", err)
	}

	networkName := fmt.Sprintf("vault-benchmark-%v", uuid)

	networkCleanup := dockertest.CreateNetwork(t, networkName)
	defer networkCleanup()

	// Create Vault Container
	vaultCleanup, containerName := dockertest.CreateVaultContainer(t, networkName)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", containerName)
	_, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, networkName, vaultAddr, "invalid_token", "userpass.hcl")

	if exitCode != 1 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestUserpass_Invalid_Config_Docker(t *testing.T) {
	t.Parallel()

	// Create Network
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal("error generating uuid for network name: %w", err)
	}

	networkName := fmt.Sprintf("vault-benchmark-%v", uuid)

	networkCleanup := dockertest.CreateNetwork(t, networkName)
	defer networkCleanup()

	// Create Vault Container
	vaultCleanup, containerName := dockertest.CreateVaultContainer(t, networkName)
	defer vaultCleanup()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http:/%s:8200", containerName)
	_, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, networkName, vaultAddr, "root", "nvalid_userpass.hcl")

	if exitCode != 1 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
