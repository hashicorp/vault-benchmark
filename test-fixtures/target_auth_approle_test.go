package testfixtures

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault-benchmark/docker/benchmarkdocker"

	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func TestEtcd3Backend(t *testing.T) {
	rootToken, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	runner, err := dockhelper.NewServiceRunner(dockhelper.RunOptions{
		ContainerName: "vault",
		NetworkName:   "vault-ellie",
		ImageRepo:     "docker.mirror.hashicorp.services/hashicorp/vault",
		ImageTag:      "latest",
		Cmd: []string{
			"server", "-log-level=trace", "-dev", fmt.Sprintf("-dev-root-token-id=%s", rootToken),
			"-dev-listen-address=0.0.0.0:8200",
		},
		Ports: []string{"8200/tcp"},
	})

	fmt.Println("error starting new runner", err)

	result, err := runner.Start(context.Background(), false, false)

	fmt.Println("result address", result.Addrs)

	fmt.Println("result of vault container", result)

	// benchmark containers
	_, _ = benchmarkdocker.PrepareTestContainer(t, result.Addrs[0], rootToken)
}
