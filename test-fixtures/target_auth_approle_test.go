package testfixtures

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault-benchmark/command"
	"github.com/hashicorp/vault-benchmark/docker/benchmarkdocker"
	"github.com/hashicorp/vault/sdk/helper/testcluster"
	"github.com/hashicorp/vault/sdk/helper/testcluster/docker"
	// "github.com/hashicorp/vault/helper/testhelpers/etcd"
)

func TestEtcd3Backend(t *testing.T) {
	// vault containers
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

	// defer cluster.Cleanup()

	client := cluster.Nodes()[0].APIClient()

	vaultAddr := client.Address()
	vaultToken := cluster.GetRootToken()
	certAddr := cluster.GetCACertPEMFile()

	os.Setenv("VAULT_ADDR", client.Address())
	fmt.Println("VAULT_ADDR", client.Address())
	os.Setenv("VAULT_TOKEN", cluster.GetRootToken())
	fmt.Println("VAULT_TOKEN", cluster.GetRootToken())
	os.Setenv("VAULT_CACERT", cluster.GetCACertPEMFile())
	fmt.Println("VAULT_CACERT", cluster.GetCACertPEMFile())

	args := []string{"run", "-config=./approle.hcl"}

	if command.Run(args) != 0 {
		t.Fatal("Non-zero response")
	}

	// benchmark containers
	_, _ = benchmarkdocker.PrepareTestContainer(t, vaultAddr, vaultToken, certAddr)
}
