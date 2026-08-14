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
	RedshiftSecretTestType   = "redshift_secret"
	RedshiftSecretTestMethod = "GET"
	RedshiftUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "REDSHIFT_USERNAME"
	RedshiftPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "REDSHIFT_PASSWORD"
)

func init() {
	TestList[RedshiftSecretTestType] = func() BenchmarkBuilder { return &RedshiftSecret{} }
}

type RedshiftSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *RedshiftSecretConfig
	logger     hclog.Logger
}

type RedshiftSecretConfig struct {
	RedshiftDBConfig   *RedshiftDBConfig   `hcl:"db_connection,block"`
	RedshiftRoleConfig *RedshiftRoleConfig `hcl:"role,block"`
}

type RedshiftDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection,optional"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	ConnectionURL          string   `hcl:"connection_url"`
	MaxOpenConnections     int      `hcl:"max_open_connections,optional"`
	MaxIdleConnections     int      `hcl:"max_idle_connections,optional"`
	MaxConnectionLifetime  string   `hcl:"max_connection_lifetime,optional"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
	DisableEscaping        bool     `hcl:"disable_escaping,optional"`
}

type RedshiftRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
	RollbackStatements   string `hcl:"rollback_statements,optional"`
	RenewStatements      string `hcl:"renew_statements,optional"`
	RotationStatements   string `hcl:"rotation_statements,optional"`
}


func (r *RedshiftSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *RedshiftSecretConfig `hcl:"config,block"`
	}{
		Config: &RedshiftSecretConfig{
			RedshiftDBConfig: &RedshiftDBConfig{
				Name:         "benchmark-redshift",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "redshift-database-plugin",
				Username:     os.Getenv(RedshiftUsernameEnvVar),
				Password:     os.Getenv(RedshiftPasswordEnvVar),
			},
			RedshiftRoleConfig: &RedshiftRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-redshift",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	r.config = testConfig.Config

	if r.config.RedshiftDBConfig.Username == "" {
		return fmt.Errorf("no redshift username provided but required")
	}

	if r.config.RedshiftDBConfig.Password == "" {
		return fmt.Errorf("no redshift password provided but required")
	}

	// Ensure creation statements are provided as they are required for Redshift
	if r.config.RedshiftRoleConfig.CreationStatements == "" {
		return fmt.Errorf("creation_statements are required for redshift role configuration")
	}

	return nil
}

func (r *RedshiftSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RedshiftSecretTestType)

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
	if err := writeStruct(client, filepath.Join(secretPath, "config", r.config.RedshiftDBConfig.Name), r.config.RedshiftDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", r.config.RedshiftRoleConfig.Name), r.config.RedshiftRoleConfig); err != nil {
		return nil, err
	}

	return &RedshiftSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RedshiftRoleConfig.Name,
		logger:     r.logger,
	}, nil
}

func (r *RedshiftSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedshiftSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *RedshiftSecret) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *RedshiftSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedshiftSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RedshiftSecret) Flags(fs *flag.FlagSet) {}
