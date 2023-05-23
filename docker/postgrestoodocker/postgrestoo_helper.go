package postgrestoodocker

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/docker"
)

func PrepareTestContainer(t *testing.T, version string) (func(), string) {
	repo := "docker.mirror.hashicorp.services/postgres"
	p := "secret"
	env := []string{
		fmt.Sprintf("POSTGRES_PASSWORD=%s", p),
		"POSTGRES_DB=database",
	}

	// _, cleanup, url, _ := prepareTestContainer(t, "postgres", "docker.mirror.hashicorp.services/postgres", version, "secret", true, false, false, env)
	runOpts := docker.RunOptions{
		ContainerName:   "postgres",
		ImageRepo:       repo,
		ImageTag:        "13.4-buster",
		Env:             env,
		Ports:           []string{"5432/tcp"},
		DoNotAutoRemove: false,
	}

	runner, err := docker.NewServiceRunner(runOpts)

	if err != nil {
		t.Fatalf("Could not start docker client for postgres: %s", err)
	}

	svc, _, err := runner.StartNewService(context.Background(), true, false, connectPostgres(p, repo))
	if err != nil {
		t.Fatalf("Could not start docker postgres service: %s", err)
	}

	return svc.Cleanup, svc.Config.URL().String()
}

func connectPostgres(password, repo string) docker.ServiceAdapter {
	return func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword("postgres", password),
			Host:     fmt.Sprintf("%s:%d", host, port),
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
		return docker.NewServiceURL(u), nil
	}
}
