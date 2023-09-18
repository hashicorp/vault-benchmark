// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dockertest

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

const (
	postgresImageRepo = "postgres"
	postgresImageTag  = "latest"
)

func CreatePostgresContainer(t *testing.T) (func(), string) {
	ctx := context.Background()

	runOpts := dockhelper.RunOptions{
		ContainerName: "postgres",
		ImageRepo:     postgresImageRepo,
		ImageTag:      postgresImageTag,
		Env:           []string{"POSTGRES_USER=username", "POSTGRES_PASSWORD=password"},
		Ports:         []string{"5432/tcp"},
	}

	runner, err := dockhelper.NewServiceRunner(runOpts)
	if err != nil {
		t.Fatalf("Error starting docker client for postgres: %s", err)
	}

	svc, err := runner.Start(ctx, true, false)

	if err != nil {
		t.Fatalf("Error starting postgres container: %s", err)
	}

	var netName string
	for netName = range svc.Container.NetworkSettings.Networks {
		// Networks above is a map; we just need to find the first and
		// only key of this map (network name). The range handles this
		// for us, but we need a loop construction in order to use range.
	}

	containerIPAddress := svc.Container.NetworkSettings.Networks[netName].IPAddress

	cleanup := func() {
		err := runner.DockerAPI.ContainerRemove(ctx, svc.Container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Error removing postgres container: %s", err)
		}
	}

	return cleanup, containerIPAddress
}
