// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package dockertest

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault-benchmark/helper/dockertest"
	"github.com/hashicorp/vault-benchmark/helper/dockertest/dockerjobs"
)

func TestKVV2_NoStoreMetadata_Docker(t *testing.T) {
	t.Parallel()

	vaultCleanup, containerIPAddress := dockertest.CreateVaultContainer(t)
	defer vaultCleanup()

	vaultAddr := fmt.Sprintf("http://%s:8200", containerIPAddress)
	benchmarkCleanup, exitCode := dockerjobs.CreateVaultBenchmarkContainer(t, vaultAddr, "root", "kvv2_no_store_metadata.hcl")
	defer benchmarkCleanup()

	if exitCode != 0 {
		t.Fatalf("Unexpected error code: %v", exitCode)
	}
}
