package dockertest

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func CreateVaultContainer(t *testing.T, networkName string) (func(), string) {
	ctx := context.Background()

	runOpts := dockhelper.RunOptions{
		ContainerName: "vault",
		NetworkName:   networkName,
		ImageRepo:     "docker.mirror.hashicorp.services/hashicorp/vault",
		ImageTag:      "latest",
		Cmd: []string{
			"server", "-log-level=trace", "-dev", fmt.Sprintf("-dev-root-token-id=%s", "root"),
			"-dev-listen-address=0.0.0.0:8200",
		},
		Ports: []string{"8200/tcp"},
	}

	runner, err := dockhelper.NewServiceRunner(runOpts)

	if err != nil {
		t.Fatalf("Error starting docker client for vault: %s", err)
	}

	result, err := runner.Start(ctx, true, false)

	if err != nil {
		t.Fatalf("Error starting vault container: %s", err)
	}

	cleanup := func() {
		err := runner.DockerAPI.ContainerRemove(ctx, result.Container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Error removing vault container: %s", err)
		}
	}

	return cleanup, result.Container.Name
}
