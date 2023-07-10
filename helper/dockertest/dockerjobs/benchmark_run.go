package dockerjobs

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func CreateVaultBenchmarkContainer(t *testing.T, vaultAddr string, vaultToken string, configFile string) (func(), int64) {
	ctx := context.Background()
	volume := map[string]string{
		"configs/": "/etc/",
	}

	runOpts := dockhelper.RunOptions{
		ContainerName:   "vault-benchmark",
		ImageRepo:       "docker.mirror.hashicorp.services/hashicorp/vault-benchmark",
		ImageTag:        "0.1",
		DoNotAutoRemove: true,
		Env:             []string{fmt.Sprintf("VAULT_ADDR=%s", vaultAddr), fmt.Sprintf("VAULT_TOKEN=%s", vaultToken)},
		CopyFromTo:      volume,
		Cmd:             []string{"/bin/vault-benchmark", "run", fmt.Sprintf("-config=/etc/%s", configFile)},
	}

	runner, err := dockhelper.NewServiceRunner(runOpts)
	if err != nil {
		t.Fatalf("Error starting docker client for benchmark: %s", err)
	}

	service, err := runner.Start(ctx, true, false)
	if err != nil {
		t.Fatalf("Error running docker client for benchmark: %s", err)
	}

	exitCh, errCh := runner.DockerAPI.ContainerWait(ctx, service.Container.ID, container.WaitConditionNotRunning)

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
		exitCode = status.StatusCode
	}

	cleanup := func() {
		err := runner.DockerAPI.ContainerRemove(ctx, service.Container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Error removing vault container: %s", err)
		}
	}

	return cleanup, exitCode
}
