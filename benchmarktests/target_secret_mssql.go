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
	MSSQLSecretTestType   = "mssql_secret"
	MSSQLSecretTestMethod = "GET"
	MSSQLUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "MSSQL_USERNAME"
	MSSQLPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "MSSQL_PASSWORD"
)

func init() {
	TestList[MSSQLSecretTestType] = func() BenchmarkBuilder { return &MSSQLSecret{} }
}

type MSSQLSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *MSSQLSecretConfig
	logger     hclog.Logger
}

type MSSQLSecretConfig struct {
	MSSQLDBConfig   *MSSQLDBConfig   `hcl:"db_connection,block"`
	MSSQLRoleConfig *MSSQLRoleConfig `hcl:"role,block"`
}

type MSSQLDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection,optional"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	ConnectionURL          string   `hcl:"connection_url"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	DisableEscaping        bool     `hcl:"disable_escaping,optional"`
	MaxOpenConnections     int      `hcl:"max_open_connections,optional"`
	MaxIdleConnections     int      `hcl:"max_idle_connections,optional"`
	MaxConnectionLifetime  string   `hcl:"max_connection_lifetime,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
	ContainedDB            bool     `hcl:"contained_db,optional"`
}

type MSSQLRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
}

func (m *MSSQLSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *MSSQLSecretConfig `hcl:"config,block"`
	}{
		Config: &MSSQLSecretConfig{
			MSSQLDBConfig: &MSSQLDBConfig{
				Name:         "benchmark-mssql",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "mssql-database-plugin",
				Username:     os.Getenv(MSSQLUsernameEnvVar),
				Password:     os.Getenv(MSSQLPasswordEnvVar),
			},
			MSSQLRoleConfig: &MSSQLRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-mssql",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	m.config = testConfig.Config

	if m.config.MSSQLDBConfig.Username == "" {
		return fmt.Errorf("no mssql username provided but required")
	}

	if m.config.MSSQLDBConfig.Password == "" {
		return fmt.Errorf("no mssql password provided but required")
	}

	return nil
}

func (m *MSSQLSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	m.logger = targetLogger.Named(MSSQLSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	m.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := m.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, filepath.Join(secretPath, "config", m.config.MSSQLDBConfig.Name), m.config.MSSQLDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", m.config.MSSQLRoleConfig.Name), m.config.MSSQLRoleConfig); err != nil {
		return nil, err
	}

	return &MSSQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   m.config.MSSQLRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *MSSQLSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: MSSQLSecretTestMethod,
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MSSQLSecret) Cleanup(client *api.Client) error {
	return cleanupMount(m.logger, client, m.pathPrefix)
}

func (m *MSSQLSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MSSQLSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MSSQLSecret) Flags(fs *flag.FlagSet) {}
