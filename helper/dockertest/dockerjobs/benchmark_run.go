package dockerjobs

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func CreateVaultBenchmarkContainer(t *testing.T, networkName string, vaultAddr string, vaultToken string) (func(), int64) {
	ctx := context.Background()
	volume := map[string]string{
		"configs/": "/etc/",
	}

	runOpts := dockhelper.RunOptions{
		ContainerName: "vault-benchmark",
		ImageRepo:     "docker.mirror.hashicorp.services/hashicorp/vault-benchmark",
		NetworkName:   networkName,
		ImageTag:      "0.1",
		Env:           []string{fmt.Sprintf("VAULT_ADDR=%s", vaultAddr), fmt.Sprintf("VAULT_TOKEN=%s", vaultToken)},
		CopyFromTo:    volume,
		Cmd:           []string{"/bin/vault-benchmark", "run", "-config=/etc/approle.hcl"},
	}

	runner, err := dockhelper.NewServiceRunner(runOpts)

	if err != nil {
		t.Fatalf("Error starting docker client for benchmark: %s", err)
	}

	result, err := runner.Start(ctx, true, false)
	containerID := result.Container.ID

	exitCh, errCh := runner.DockerAPI.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)

	if err != nil {
		t.Fatalf("Error starting vault-benchmark container: %s", err)
	}

	// wait until benchmark exit
	var exitCode int64
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case status := <-exitCh:
		statusCode := status.StatusCode
		exitCode = statusCode
	}

	cleanup := func() {
		err := runner.DockerAPI.ContainerRemove(ctx, result.Container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Error removing vault container: %s", err)
		}
	}

	return cleanup, exitCode
}
