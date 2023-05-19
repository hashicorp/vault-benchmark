// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"os"
	"testing"

	"github.com/hashicorp/vault-benchmark/command"
	"github.com/hashicorp/vault/sdk/helper/testcluster"
	"github.com/hashicorp/vault/sdk/helper/testcluster/docker"
)

// TestRaft_Configuration_Docker is a variant of TestRaft_Configuration that
// uses docker containers for the vault nodes.
func TestApprole_Auth_Docker(t *testing.T) {
	binary := os.Getenv("VAULT_BINARY")
	if binary == "" {
		t.Skip("only running docker test when $VAULT_BINARY present")
	}
	opts := &docker.DockerClusterOptions{
		ImageRepo: "hashicorp/vault",
		ImageTag:  "latest",
		ClusterOptions: testcluster.ClusterOptions{
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
			},
		},
	}
	cluster := docker.NewTestDockerCluster(t, opts)

	defer cluster.Cleanup()

	client := cluster.Nodes()[0].APIClient()

	os.Setenv("VAULT_ADDR", client.Address())
	os.Setenv("VAULT_TOKEN", cluster.GetRootToken())
	os.Setenv("VAULT_CACERT", cluster.GetCACertPEMFile())

	args := []string{"run", "-config=./approle.hcl"}

	if command.Run(args) != 0 {
		t.Fatal("Non-zero response")
	}
}
