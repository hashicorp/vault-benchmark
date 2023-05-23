package benchmarkdocker

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"testing"

	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
)

func PrepareTestContainer(t *testing.T, vaultAddr string, vaultToken string) (func(), string) {
	repo := "docker.mirror.hashicorp.services/hashicorp/vault-benchmark"
	volume := map[string]string{
		"configs/": "/etc/",
	}

	runOpts := dockhelper.RunOptions{
		ContainerName: "vault-benchmark",
		ImageRepo:     repo,
		NetworkName:   "vault-ellie",
		ImageTag:      "0.1",
		Env:           []string{"VAULT_ADDR=http://vault:8200", fmt.Sprintf("VAULT_TOKEN=%v", vaultToken)},
		// Ports:           []string{"5432/tcp"},
		// if true container will stay, if false, container will be deleted
		DoNotAutoRemove: true,
		CopyFromTo:      volume,
		Cmd:             []string{"/bin/vault-benchmark", "run", "-config=/etc/approle.hcl"},
	}

	runner, err := dockhelper.NewServiceRunner(runOpts)

	if err != nil {
		t.Fatalf("Could not start docker client for benchmark: %s", err)
	}

	// cfg := &container.Config{
	// 	Hostname: runner.RunOptions.ContainerName,
	// 	Image:    fmt.Sprintf("%s:%s", runner.RunOptions.ImageRepo, runner.RunOptions.ImageTag),
	// 	Env:      runner.RunOptions.Env,
	// 	Cmd:      runner.RunOptions.Cmd,
	// }

	// if len(runner.RunOptions.Ports) > 0 {
	// 	cfg.ExposedPorts = make(map[nat.Port]struct{})
	// 	for _, p := range runner.RunOptions.Ports {
	// 		cfg.ExposedPorts[nat.Port(p)] = struct{}{}
	// 	}
	// }
	// if len(runner.RunOptions.Entrypoint) > 0 {
	// 	cfg.Entrypoint = strslice.StrSlice(runner.RunOptions.Entrypoint)
	// }

	// var opts types.ImageCreateOptions
	// if runner.RunOptions.AuthUsername != "" && runner.RunOptions.AuthPassword != "" {
	// 	var buf bytes.Buffer
	// 	auth := map[string]string{
	// 		"username": runner.RunOptions.AuthUsername,
	// 		"password": runner.RunOptions.AuthPassword,
	// 	}
	// 	if err := json.NewEncoder(&buf).Encode(auth); err != nil {
	// 		return nil, ""
	// 	}
	// 	opts.RegistryAuth = base64.URLEncoding.EncodeToString(buf.Bytes())
	// }

	result, err := runner.Start(context.Background(), true, false)
	fmt.Println("RESULT", result)
	return nil, ""
}

func connect() dockhelper.ServiceAdapter {
	return func(ctx context.Context, host string, port int) (dockhelper.ServiceConfig, error) {
		u := url.URL{
			Scheme:   "postgres",
			Path:     "postgres",
			RawQuery: "sslmode=disable",
		}

		db, err := sql.Open("pgx", u.String())
		if err != nil {
			return nil, err
		}
		defer db.Close()

		if err = db.Ping(); err != nil {
			return nil, err
		}
		return dockhelper.NewServiceURL(u), nil
	}
}
