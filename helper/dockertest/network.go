package dockertest

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func CreateNetwork(t *testing.T, name string) func() {
	dockerClient, err := dockhelper.NewDockerAPI()

	if err != nil {
		t.Fatalf("Error connecting to docker client: %s", err)
	}

	network, err := dockerClient.NetworkCreate(context.Background(), name, types.NetworkCreate{})

	if err != nil {
		t.Fatalf("Error creating network: %s", err)
	}

	networkID := network.ID

	cleanup := func() {
		err := dockerClient.NetworkRemove(context.Background(), networkID)

		if err != nil {
			t.Fatalf("Error removing network: %s", err)
		}
	}

	return cleanup
}
