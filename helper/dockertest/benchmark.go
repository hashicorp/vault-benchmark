package dockertest

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func CreateVaultBenchmarkContainer(t *testing.T, networkName string, vaultAddr string, vaultToken string) func() {
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

	if err != nil {
		t.Fatalf("Error starting vault-benchmark container: %s", err)
	}

	cleanup := func() {
		err := runner.DockerAPI.ContainerRemove(ctx, result.Container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Error removing vault-benchmark container: %s", err)
		}
	}

	return cleanup
}
