package dockerjobs

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

type VaultBenchmark struct {
	dockhelper.RunOptions
}

func CreateVaultBenchmarkContainer(t *testing.T, vaultAddr string, vaultToken string, configFile string) (func(), int64) {
	ctx := context.Background()
	binary := os.Getenv("BENCHMARK_BINARY")

	if binary == "" {
		t.Skip("only running docker test when $BENCHMARK_BINARY present")
	}

	api, err := dockhelper.NewDockerAPI()
	imageRepo := "hashicorp/vault-benchmark"
	imageTag := "latest"
	tag, err := setupBenchmarkImage(ctx, imageRepo, imageTag, binary, api)

	volume := map[string]string{
		"configs/": "/etc/",
	}

	runOpts := dockhelper.RunOptions{
		ContainerName:   "vault-benchmark",
		ImageRepo:       imageRepo,
		ImageTag:        tag,
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
	containerID := service.Container.ID

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
		err := runner.DockerAPI.ContainerRemove(ctx, service.Container.ID, types.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Fatalf("Error removing vault container: %s", err)
		}
	}

	return cleanup, exitCode
}

func setupBenchmarkImage(ctx context.Context, imageRepo string, imageTag string, binary string, dAPI *client.Client) (string, error) {
	suffix := "testing"

	tag := imageTag + "-" + suffix

	f, err := os.Open(binary)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	bCtx := dockhelper.NewBuildContext()
	bCtx["vault-benchmark"] = &dockhelper.FileContents{
		Data: data,
		Mode: 0o755,
	}

	containerFile := fmt.Sprintf(`
FROM %s:%s
COPY vault-benchmark /bin/vault-benchmark
`, imageRepo, imageTag)

	_, err = dockhelper.BuildImage(ctx, dAPI, containerFile, bCtx,
		dockhelper.BuildRemove(true), dockhelper.BuildForceRemove(true),
		dockhelper.BuildPullParent(true),
		dockhelper.BuildTags([]string{imageRepo + ":" + tag}))
	if err != nil {
		return "", err
	}
	// dc.builtTags[tag] = struct{}{}
	return tag, nil
}
