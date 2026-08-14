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
	MySQLSecretTestType   = "mysql_secret"
	MySQLSecretTestMethod = "GET"
	MySQLUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "MYSQL_USERNAME"
	MySQLPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "MYSQL_PASSWORD"
)

func init() {
	TestList[MySQLSecretTestType] = func() BenchmarkBuilder { return &MySQLSecret{} }
}

type MySQLSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *MySQLSecretConfig
	logger     hclog.Logger
}

type MySQLSecretConfig struct {
	MySQLDBConfig   *MySQLDBConfig   `hcl:"db_connection,block"`
	MySQLRoleConfig *MySQLRoleConfig `hcl:"role,block"`
}

type MySQLDBConfig struct {
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
	TLSCertificateKey      string   `hcl:"tls_certificate_key,optional"`
	TLSCACertificate       string   `hcl:"tls_ca,optional"`
	TLSServerName          string   `hcl:"tls_server_name,optional"`
	TLSSkipVerify          bool     `hcl:"tls_skip_verify,optional"`
}

type MySQLRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
}

func (m *MySQLSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *MySQLSecretConfig `hcl:"config,block"`
	}{
		Config: &MySQLSecretConfig{
			MySQLDBConfig: &MySQLDBConfig{
				Name:         "benchmark-mysql",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "mysql-database-plugin",
				Username:     os.Getenv(MySQLUsernameEnvVar),
				Password:     os.Getenv(MySQLPasswordEnvVar),
			},
			MySQLRoleConfig: &MySQLRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-mysql",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	m.config = testConfig.Config

	if m.config.MySQLDBConfig.Username == "" {
		return fmt.Errorf("no mysql username provided but required")
	}

	if m.config.MySQLDBConfig.Password == "" {
		return fmt.Errorf("no mysql password provided but required")
	}

	return nil
}

func (m *MySQLSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	m.logger = targetLogger.Named(MySQLSecretTestType)

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
	if err := writeStruct(client, filepath.Join(secretPath, "config", m.config.MySQLDBConfig.Name), m.config.MySQLDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", m.config.MySQLRoleConfig.Name), m.config.MySQLRoleConfig); err != nil {
		return nil, err
	}

	return &MySQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   m.config.MySQLRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *MySQLSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: MySQLSecretTestMethod,
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MySQLSecret) Cleanup(client *api.Client) error {
	return cleanupMount(m.logger, client, m.pathPrefix)
}

func (m *MySQLSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MySQLSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MySQLSecret) Flags(fs *flag.FlagSet) {}
