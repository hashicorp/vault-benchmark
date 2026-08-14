// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	RedisDynamicSecretTestType         = "redis_dynamic_secret"
	RedisDynamicSecretTestMethod       = "GET"
	RedisDynamicSecretDBUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "REDIS_USERNAME"
	RedisDynamicSecretDBPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "REDIS_PASSWORD"
)

func init() {
	TestList[RedisDynamicSecretTestType] = func() BenchmarkBuilder { return &RedisDynamicSecret{} }
}

type RedisDynamicSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *RedisDynamicSecretConfig
	logger     hclog.Logger
}

type RedisDynamicSecretConfig struct {
	DBConfig   *RedisDBConfig          `hcl:"db_connection,block"`
	RoleConfig *RedisDynamicRoleConfig `hcl:"role,block"`
}

type RedisDynamicRoleConfig struct {
	Name               string `hcl:"name,optional"`
	DBName             string `hcl:"db_name,optional"`
	DefaultTTL         string `hcl:"default_ttl,optional"`
	MaxTTL             string `hcl:"max_ttl,optional"`
	CreationStatements string `hcl:"creation_statements"`
}

func (r *RedisDynamicSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *RedisDynamicSecretConfig `hcl:"config,block"`
	}{
		Config: &RedisDynamicSecretConfig{
			DBConfig: &RedisDBConfig{
				Name:         "benchmark-redis-db",
				PluginName:   "redis-database-plugin",
				AllowedRoles: []string{"my-*-role"},
				Username:     os.Getenv(RedisDynamicSecretDBUsernameEnvVar),
				Password:     os.Getenv(RedisDynamicSecretDBPasswordEnvVar),
			},
			RoleConfig: &RedisDynamicRoleConfig{
				Name:   "my-dynamic-role",
				DBName: "benchmark-redis-db",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	r.config = testConfig.Config

	if r.config.DBConfig.Username == "" {
		return fmt.Errorf("no redis username provided but required")
	}

	if r.config.DBConfig.Password == "" {
		return fmt.Errorf("no redis password provided but required")
	}

	return nil
}

func (r *RedisDynamicSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RedisDynamicSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	r.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, filepath.Join(secretPath, "config", r.config.DBConfig.Name), r.config.DBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", r.config.RoleConfig.Name), r.config.RoleConfig); err != nil {
		return nil, err
	}

	return &RedisDynamicSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RoleConfig.Name,
		config:     r.config,
		logger:     r.logger,
	}, nil
}

func (r *RedisDynamicSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedisDynamicSecretTestMethod,
		URL:    fmt.Sprintf("%s%s/creds/%s", client.Address(), r.pathPrefix, r.roleName),
		Header: r.header,
	}
}

func (r *RedisDynamicSecret) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *RedisDynamicSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedisDynamicSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RedisDynamicSecret) Flags(fs *flag.FlagSet) {}
