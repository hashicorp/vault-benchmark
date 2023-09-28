package dockertest

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

func TestPostgres_Secret_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, vaultContainerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Create Postgres Container
	postgresCleanup, postgresContainerIPAddress := dockertest.CreatePostgresContainer(t)
	defer postgresCleanup()

	cleanupHCL, newHCLFile := editHCL(t, "./configs/postgres.hcl", "<container_addr>", postgresContainerIPAddress)
	defer cleanupHCL()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", vaultContainerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", filepath.Base(newHCLFile))
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}

func TestPostgres_Invalid_Secret_Docker(t *testing.T) {
	t.Parallel()

	// Create Vault Container
	vaultCleanup, vaultContainerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	// Create Postgres Container
	postgresCleanup, postgresContainerIPAddress := dockertest.CreatePostgresContainer(t)
	defer postgresCleanup()

	cleanupHCL, newHCLFile := editHCL(t, "./configs/invalid_postgres.hcl", "<container_addr>", postgresContainerIPAddress)
	defer cleanupHCL()

	// Run Vault-Benchmark Container
	vaultAddr := fmt.Sprintf("http://%s:8200", vaultContainerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", filepath.Base(newHCLFile))
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
