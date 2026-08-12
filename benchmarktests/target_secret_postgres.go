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
	PostgreSQLSecretTestType   = "postgresql_secret"
	PostgreSQLSecretTestMethod = "GET"
	PostgreSQLUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "POSTGRES_USERNAME"
	PostgreSQLPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "POSTGRES_PASSWORD"
)

func init() {
	TestList[PostgreSQLSecretTestType] = func() BenchmarkBuilder { return &PostgreSQLSecret{} }
}

type PostgreSQLSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *PostgreSQLSecretConfig
	logger     hclog.Logger
}

type PostgreSQLSecretConfig struct {
	PostgreSQLDBConfig   *PostgreSQLDBConfig   `hcl:"db_connection,block"`
	PostgreSQLRoleConfig *PostgreSQLRoleConfig `hcl:"role,block"`
}

type PostgreSQLDBConfig struct {
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

type PostgreSQLRoleConfig struct {
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


func (s *PostgreSQLSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *PostgreSQLSecretConfig `hcl:"config,block"`
	}{
		Config: &PostgreSQLSecretConfig{
			PostgreSQLDBConfig: &PostgreSQLDBConfig{
				Name:         "benchmark-postgres",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "postgresql-database-plugin",
				Username:     os.Getenv(PostgreSQLUsernameEnvVar),
				Password:     os.Getenv(PostgreSQLPasswordEnvVar),
			},
			PostgreSQLRoleConfig: &PostgreSQLRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-postgres",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	s.config = testConfig.Config

	if s.config.PostgreSQLDBConfig.Username == "" {
		return fmt.Errorf("no postgres username provided but required")
	}

	if s.config.PostgreSQLDBConfig.Password == "" {
		return fmt.Errorf("no postgres password provided but required")
	}

	return nil
}

func (s *PostgreSQLSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	s.logger = targetLogger.Named(PostgreSQLSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	s.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := s.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, filepath.Join(secretPath, "config", s.config.PostgreSQLDBConfig.Name), s.config.PostgreSQLDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", s.config.PostgreSQLRoleConfig.Name), s.config.PostgreSQLRoleConfig); err != nil {
		return nil, err
	}

	return &PostgreSQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   s.config.PostgreSQLRoleConfig.Name,
		logger:     s.logger,
	}, nil

}

func (s *PostgreSQLSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: PostgreSQLSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *PostgreSQLSecret) Cleanup(client *api.Client) error {
	return cleanupMount(s.logger, client, s.pathPrefix)
}

func (s *PostgreSQLSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     PostgreSQLSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (l *PostgreSQLSecret) Flags(fs *flag.FlagSet) {}
