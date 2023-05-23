package postgresqldocker

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/docker"
)

func prepareTestContainer(t *testing.T, name, repo, version, password string,
	addSuffix, forceLocalAddr, doNotAutoRemove bool, envVars []string,
) (*docker.Runner, func(), string, string) {
	if os.Getenv("PG_URL") != "" {
		return nil, func() {}, "", os.Getenv("PG_URL")
	}

	if version == "" {
		version = "11"
	}

	runOpts := docker.RunOptions{
		ContainerName:   name,
		ImageRepo:       repo,
		ImageTag:        version,
		Env:             envVars,
		Ports:           []string{"5432/tcp"},
		DoNotAutoRemove: doNotAutoRemove,
	}
	if repo == "bitnami/postgresql-repmgr" {
		runOpts.NetworkID = os.Getenv("POSTGRES_MULTIHOST_NET")
	}

	runner, err := docker.NewServiceRunner(runOpts)
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	svc, containerID, err := runner.StartNewService(context.Background(), addSuffix, forceLocalAddr, connectPostgres(password, repo))
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	return runner, svc.Cleanup, svc.Config.URL().String(), containerID
}

func PrepareTestContainer(t *testing.T, version string) (func(), string) {
	env := []string{
		"POSTGRES_PASSWORD=secret",
		"POSTGRES_DB=database",
	}

	_, cleanup, url, _ := prepareTestContainer(t, "postgres", "docker.mirror.hashicorp.services/postgres", version, "secret", true, false, false, env)

	return cleanup, url
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
