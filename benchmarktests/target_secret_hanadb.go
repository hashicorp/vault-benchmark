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
	HanaDBSecretTestType   = "hanadb_secret"
	HanaDBSecretTestMethod = "GET"
	HanaDBUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "HANADB_USERNAME"
	HanaDBPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "HANADB_PASSWORD"
)

func init() {
	TestList[HanaDBSecretTestType] = func() BenchmarkBuilder { return &HanaDBSecret{} }
}

type HanaDBSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *HanaDBSecretConfig
	logger     hclog.Logger
}

type HanaDBSecretConfig struct {
	HanaDBDBConfig   *HanaDBDBConfig   `hcl:"db_connection,block"`
	HanaDBRoleConfig *HanaDBRoleConfig `hcl:"role,block"`
}

type HanaDBDBConfig struct {
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
	TLSCACertificate       string   `hcl:"tls_ca_certificate,optional"`
	TLSServerName          string   `hcl:"tls_server_name,optional"`
	TLSSkipVerify          bool     `hcl:"tls_skip_verify,optional"`
}

type HanaDBRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
}

func (m *HanaDBSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *HanaDBSecretConfig `hcl:"config,block"`
	}{
		Config: &HanaDBSecretConfig{
			HanaDBDBConfig: &HanaDBDBConfig{
				Name:         "benchmark-hanadb",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "hana-database-plugin",
				Username:     os.Getenv(HanaDBUsernameEnvVar),
				Password:     os.Getenv(HanaDBPasswordEnvVar),
			},
			HanaDBRoleConfig: &HanaDBRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-hanadb",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	m.config = testConfig.Config

	if m.config.HanaDBDBConfig.Username == "" {
		return fmt.Errorf("no hanadb username provided but required")
	}

	if m.config.HanaDBDBConfig.Password == "" {
		return fmt.Errorf("no hanadb password provided but required")
	}

	return nil
}

func (m *HanaDBSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	m.logger = targetLogger.Named(HanaDBSecretTestType)

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
	if err := writeStruct(client, filepath.Join(secretPath, "config", m.config.HanaDBDBConfig.Name), m.config.HanaDBDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", m.config.HanaDBRoleConfig.Name), m.config.HanaDBRoleConfig); err != nil {
		return nil, err
	}

	return &HanaDBSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   m.config.HanaDBRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *HanaDBSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: HanaDBSecretTestMethod,
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *HanaDBSecret) Cleanup(client *api.Client) error {
	return cleanupMount(m.logger, client, m.pathPrefix)
}

func (m *HanaDBSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     HanaDBSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *HanaDBSecret) Flags(fs *flag.FlagSet) {}
