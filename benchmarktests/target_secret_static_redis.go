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
	RedisStaticSecretTestType       = "redis_static_secret"
	RedisStaticSecretTestMethod     = "GET"
	RedisStaticSecretUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "STATIC_REDIS_USERNAME"
	RedisStaticSecretPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "STATIC_REDIS_PASSWORD"
)

func init() {
	TestList[RedisStaticSecretTestType] = func() BenchmarkBuilder { return &RedisStaticSecret{} }
}

type RedisStaticSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *RedisStaticSecretConfig
	logger     hclog.Logger
}

type RedisStaticSecretConfig struct {
	DBConfig   *RedisDBConfig         `hcl:"db_connection,block"`
	RoleConfig *RedisStaticRoleConfig `hcl:"role,block"`
}

type RedisDBConfig struct {
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	PluginVersion    string   `hcl:"plugin_version,optional"`
	VerifyConnection *bool    `hcl:"verify_connection,optional"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`
	CACert           string   `hcl:"ca_cert,optional"`

	Host           string `hcl:"host"`
	Port           int    `hcl:"port"`
	Username       string `hcl:"username,optional"`
	Password       string `hcl:"password,optional"`
	PasswordPolicy string `hcl:"password_policy,optional"`
	TLS            bool   `hcl:"tls,optional"`
	InsecureTLS    bool   `hcl:"insecure_tls,optional"`
}

type RedisStaticRoleConfig struct {
	Name           string `hcl:"name,optional"`
	DBName         string `hcl:"db_name,optional"`
	RotationPeriod string `hcl:"rotation_period,optional"`
	Username       string `hcl:"username"`
	InsecureTLS    bool   `hcl:"insecure_tls,optional"`
}

func (r *RedisStaticSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *RedisStaticSecretConfig `hcl:"config,block"`
	}{
		Config: &RedisStaticSecretConfig{
			DBConfig: &RedisDBConfig{
				Name:         "benchmark-redis-db",
				PluginName:   "redis-database-plugin",
				AllowedRoles: []string{"my-*-role"},
				Username:     os.Getenv(RedisStaticSecretUsernameEnvVar),
				Password:     os.Getenv(RedisStaticSecretPasswordEnvVar),
			},
			RoleConfig: &RedisStaticRoleConfig{
				DBName: "benchmark-redis-db",
				Name:   "my-static-role",
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

func (r *RedisStaticSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RedisStaticSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	r.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling database secrets engine: %v", err)
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

	return &RedisStaticSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RoleConfig.Name,
		config:     r.config,
		logger:     r.logger,
	}, nil
}

func (r *RedisStaticSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedisStaticSecretTestMethod,
		URL:    fmt.Sprintf("%s%s/creds/%s", client.Address(), r.pathPrefix, r.roleName),
		Header: r.header,
	}
}

func (r *RedisStaticSecret) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *RedisStaticSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedisStaticSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RedisStaticSecret) Flags(fs *flag.FlagSet) {}
