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
	OracleSecretTestType   = "oracle_secret"
	OracleSecretTestMethod = "GET"
	OracleUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "ORACLE_USERNAME"
	OraclePasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "ORACLE_PASSWORD"
)

func init() {
	TestList[OracleSecretTestType] = func() BenchmarkBuilder { return &OracleSecret{} }
}

type OracleSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *OracleSecretConfig
	logger     hclog.Logger
}

type OracleSecretConfig struct {
	OracleDBConfig   *OracleDBConfig   `hcl:"db_connection,block"`
	OracleRoleConfig *OracleRoleConfig `hcl:"role,block"`
}

type OracleDBConfig struct {
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
	SplitStatements        bool     `hcl:"split_statements,optional"`
	DisconnectSessions     bool     `hcl:"disconnect_sessions,optional"`
}

type OracleRoleConfig struct {
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

func (o *OracleSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *OracleSecretConfig `hcl:"config,block"`
	}{
		Config: &OracleSecretConfig{
			OracleDBConfig: &OracleDBConfig{
				Name:            "benchmark-oracle",
				AllowedRoles:    []string{"benchmark-role"},
				PluginName:      "oracle-database-plugin",
				Username:        os.Getenv(OracleUsernameEnvVar),
				Password:        os.Getenv(OraclePasswordEnvVar),
				SplitStatements: true,
			},
			OracleRoleConfig: &OracleRoleConfig{
				Name:                 "benchmark-role",
				DBName:               "benchmark-oracle",
				RevocationStatements: "DROP USER {{username}} CASCADE;",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	o.config = testConfig.Config

	if o.config.OracleDBConfig.Username == "" {
		return fmt.Errorf("no oracle username provided but required")
	}

	if o.config.OracleDBConfig.Password == "" {
		return fmt.Errorf("no oracle password provided but required")
	}

	if o.config.OracleRoleConfig.CreationStatements == "" {
		return fmt.Errorf("creation_statements is required but not provided")
	}

	return nil
}

func (o *OracleSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	o.logger = targetLogger.Named(OracleSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	o.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := o.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, filepath.Join(secretPath, "config", o.config.OracleDBConfig.Name), o.config.OracleDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", o.config.OracleRoleConfig.Name), o.config.OracleRoleConfig); err != nil {
		return nil, err
	}

	return &OracleSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   o.config.OracleRoleConfig.Name,
		logger:     o.logger,
	}, nil
}

func (o *OracleSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: OracleSecretTestMethod,
		URL:    client.Address() + o.pathPrefix + "/creds/" + o.roleName,
		Header: o.header,
	}
}

func (o *OracleSecret) Cleanup(client *api.Client) error {
	return cleanupMount(o.logger, client, o.pathPrefix)
}

func (o *OracleSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     OracleSecretTestMethod,
		pathPrefix: o.pathPrefix,
	}
}

func (o *OracleSecret) Flags(fs *flag.FlagSet) {}
