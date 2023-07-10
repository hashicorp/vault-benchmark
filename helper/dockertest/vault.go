package dockertest

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func CreateVaultContainer(t *testing.T) (func(), string) {
	ctx := context.Background()

	runOpts := dockhelper.RunOptions{
		ContainerName: "vault",
		ImageRepo:     "docker.mirror.hashicorp.services/hashicorp/vault",
		ImageTag:      "latest",
		Cmd: []string{
			"server", "-log-level=trace", "-dev", "-dev-root-token-id=root",
			"-dev-listen-address=0.0.0.0:8200",
		},
		Ports: []string{"8200/tcp"},
	}

	runner, err := dockhelper.NewServiceRunner(runOpts)

	if err != nil {
		t.Fatalf("Error starting docker client for vault: %s", err)
	}

	svc, err := runner.Start(ctx, true, false)

	if err != nil {
		t.Fatalf("Error starting vault container: %s", err)
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
			t.Fatalf("Error removing vault container: %s", err)
		}
	}

	return cleanup, containerIPAddress
}
