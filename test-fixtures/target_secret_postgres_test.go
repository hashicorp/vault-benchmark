package dockertest

// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

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

	time.Sleep(5 * time.Second)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", filepath.Base(newHCLFile))
	defer benchmarkCleanup()

	var expectedCode int64 = 0
	if exitCode != expectedCode {
		t.Fatalf("Expected return code: %d. Actual return code: %d", expectedCode, exitCode)
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

	var expectedCode int64 = 1
	if exitCode != expectedCode {
		t.Fatalf("Expected return code: %d. Actual return code: %d", expectedCode, exitCode)
	}
}
