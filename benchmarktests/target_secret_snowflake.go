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
	SnowflakeDynamicSecretTestType = "snowflake_dynamic_secret"
	SnowflakeStaticSecretTestType  = "snowflake_static_secret"
	SnowflakeSecretTestMethod      = "GET"
	SnowflakeUsernameEnvVar        = VaultBenchmarkEnvVarPrefix + "SNOWFLAKE_USERNAME"
	SnowflakePasswordEnvVar        = VaultBenchmarkEnvVarPrefix + "SNOWFLAKE_PASSWORD"
	SnowflakePrivateKeyEnvVar      = VaultBenchmarkEnvVarPrefix + "SNOWFLAKE_PRIVATE_KEY"
	SnowflakePrivateKeyPassEnvVar  = VaultBenchmarkEnvVarPrefix + "SNOWFLAKE_PRIVATE_KEY_PASSWORD"
	SnowflakeAccountEnvVar         = VaultBenchmarkEnvVarPrefix + "SNOWFLAKE_ACCOUNT"
	SnowflakeStaticUsernameEnvVar  = VaultBenchmarkEnvVarPrefix + "SNOWFLAKE_STATIC_USERNAME"
)

func init() {
	TestList[SnowflakeDynamicSecretTestType] = func() BenchmarkBuilder { return &SnowflakeDynamicSecret{} }
	TestList[SnowflakeStaticSecretTestType] = func() BenchmarkBuilder { return &SnowflakeStaticSecret{} }
}

type SnowflakeDynamicSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *SnowflakeDynamicSecretConfig
	logger     hclog.Logger
}

type SnowflakeStaticSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *SnowflakeStaticSecretConfig
	logger     hclog.Logger
}

type SnowflakeDynamicSecretConfig struct {
	SnowflakeDBConfig   *SnowflakeDBConfig   `hcl:"db_connection,block"`
	SnowflakeRoleConfig *SnowflakeRoleConfig `hcl:"role,block"`
}

type SnowflakeStaticSecretConfig struct {
	SnowflakeDBConfig         *SnowflakeDBConfig         `hcl:"db_connection,block"`
	SnowflakeStaticRoleConfig *SnowflakeStaticRoleConfig `hcl:"static_role,block"`
}

type SnowflakeDBConfig struct {
	Name               string   `hcl:"name,optional"`
	PluginName         string   `hcl:"plugin_name,optional"`
	VerifyConnection   *bool    `hcl:"verify_connection,optional"`
	AllowedRoles       []string `hcl:"allowed_roles,optional"`
	ConnectionURL      string   `hcl:"connection_url"`
	Username           string   `hcl:"username,optional"`
	Password           string   `hcl:"password,optional"`
	PrivateKey         string   `hcl:"private_key,optional"`
	PrivateKeyPassword string   `hcl:"private_key_password,optional"`
	Account            string   `hcl:"account,optional"`
	Warehouse          string   `hcl:"warehouse,optional"`
	Database           string   `hcl:"database,optional"`
	Schema             string   `hcl:"schema,optional"`
	Role               string   `hcl:"role,optional"`
}

type SnowflakeRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
	CredentialType       string `hcl:"credential_type,optional"`
	CredentialConfig     string `hcl:"credential_config,optional"`
}

type SnowflakeStaticRoleConfig struct {
	Name               string `hcl:"name,optional"`
	DBName             string `hcl:"db_name,optional"`
	Username           string `hcl:"username"`
	RotationPeriod     string `hcl:"rotation_period,optional"`
	RotationStatements string `hcl:"rotation_statements,optional"`
	CredentialType     string `hcl:"credential_type,optional"`
	CredentialConfig   string `hcl:"credential_config,optional"`
}

func (s *SnowflakeDynamicSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *SnowflakeDynamicSecretConfig `hcl:"config,block"`
	}{
		Config: &SnowflakeDynamicSecretConfig{
			SnowflakeDBConfig: &SnowflakeDBConfig{
				Name:               "benchmark-snowflake-dynamic",
				AllowedRoles:       []string{"benchmark-dynamic-role"},
				PluginName:         "snowflake-database-plugin",
				Username:           os.Getenv(SnowflakeUsernameEnvVar),
				Password:           os.Getenv(SnowflakePasswordEnvVar),
				PrivateKey:         os.Getenv(SnowflakePrivateKeyEnvVar),
				PrivateKeyPassword: os.Getenv(SnowflakePrivateKeyPassEnvVar),
				Account:            os.Getenv(SnowflakeAccountEnvVar),
				VerifyConnection:   &[]bool{false}[0], // Default to false to avoid connection issues
			},
			SnowflakeRoleConfig: &SnowflakeRoleConfig{
				Name:   "benchmark-dynamic-role",
				DBName: "benchmark-snowflake-dynamic",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	s.config = testConfig.Config

	if s.config.SnowflakeDBConfig.Username == "" {
		return fmt.Errorf("no snowflake username provided but required")
	}

	hasPassword := s.config.SnowflakeDBConfig.Password != ""
	hasPrivateKey := s.config.SnowflakeDBConfig.PrivateKey != ""

	if !hasPassword && !hasPrivateKey {
		return fmt.Errorf("no snowflake password or private key provided but one is required")
	}

	if hasPrivateKey && s.config.SnowflakeDBConfig.Account == "" {
		return fmt.Errorf("snowflake account identifier is required when using private key authentication")
	}

	return nil
}

func (s *SnowflakeDynamicSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	s.logger = targetLogger.Named(SnowflakeDynamicSecretTestType)

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
	if err := writeStruct(client, filepath.Join(secretPath, "config", s.config.SnowflakeDBConfig.Name), s.config.SnowflakeDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", s.config.SnowflakeRoleConfig.Name), s.config.SnowflakeRoleConfig); err != nil {
		return nil, err
	}

	return &SnowflakeDynamicSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   s.config.SnowflakeRoleConfig.Name,
		logger:     s.logger,
	}, nil
}

func (s *SnowflakeDynamicSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: SnowflakeSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *SnowflakeDynamicSecret) Cleanup(client *api.Client) error {
	return cleanupMount(s.logger, client, s.pathPrefix)
}

func (s *SnowflakeDynamicSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     SnowflakeSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SnowflakeDynamicSecret) Flags(fs *flag.FlagSet) {}

func (s *SnowflakeStaticSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *SnowflakeStaticSecretConfig `hcl:"config,block"`
	}{
		Config: &SnowflakeStaticSecretConfig{
			SnowflakeDBConfig: &SnowflakeDBConfig{
				Name:               "benchmark-snowflake-static",
				AllowedRoles:       []string{"benchmark-static-role"},
				PluginName:         "snowflake-database-plugin",
				Username:           os.Getenv(SnowflakeUsernameEnvVar),
				Password:           os.Getenv(SnowflakePasswordEnvVar),
				PrivateKey:         os.Getenv(SnowflakePrivateKeyEnvVar),
				PrivateKeyPassword: os.Getenv(SnowflakePrivateKeyPassEnvVar),
				Account:            os.Getenv(SnowflakeAccountEnvVar),
				VerifyConnection:   &[]bool{false}[0], // Default to false for static roles
			},
			SnowflakeStaticRoleConfig: &SnowflakeStaticRoleConfig{
				Name:           "benchmark-static-role",
				DBName:         "benchmark-snowflake-static",
				Username:       os.Getenv(SnowflakeStaticUsernameEnvVar),
				RotationPeriod: "24h",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	s.config = testConfig.Config

	if s.config.SnowflakeDBConfig.Username == "" {
		return fmt.Errorf("no snowflake username provided but required")
	}

	if s.config.SnowflakeStaticRoleConfig.Username == "" {
		return fmt.Errorf("no static role username provided but required")
	}

	hasPassword := s.config.SnowflakeDBConfig.Password != ""
	hasPrivateKey := s.config.SnowflakeDBConfig.PrivateKey != ""

	if !hasPassword && !hasPrivateKey {
		return fmt.Errorf("no snowflake password or private key provided but one is required")
	}

	if hasPrivateKey && s.config.SnowflakeDBConfig.Account == "" {
		return fmt.Errorf("snowflake account identifier is required when using private key authentication")
	}

	// Set default rotation statements based on credential type
	if s.config.SnowflakeStaticRoleConfig.RotationStatements == "" {
		if hasPrivateKey {
			s.config.SnowflakeStaticRoleConfig.RotationStatements = "ALTER USER {{name}} SET RSA_PUBLIC_KEY='{{public_key}}'"
			if s.config.SnowflakeStaticRoleConfig.CredentialType == "" {
				s.config.SnowflakeStaticRoleConfig.CredentialType = "rsa_private_key"
			}
		} else {
			s.config.SnowflakeStaticRoleConfig.RotationStatements = "ALTER USER {{name}} SET PASSWORD = '{{password}}'"
			if s.config.SnowflakeStaticRoleConfig.CredentialType == "" {
				s.config.SnowflakeStaticRoleConfig.CredentialType = "password"
			}
		}
	}

	return nil
}

func (s *SnowflakeStaticSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	s.logger = targetLogger.Named(SnowflakeStaticSecretTestType)

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
	if err := writeStruct(client, filepath.Join(secretPath, "config", s.config.SnowflakeDBConfig.Name), s.config.SnowflakeDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("static role"))
	if err := writeStruct(client, filepath.Join(secretPath, "static-roles", s.config.SnowflakeStaticRoleConfig.Name), s.config.SnowflakeStaticRoleConfig); err != nil {
		return nil, err
	}

	return &SnowflakeStaticSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   s.config.SnowflakeStaticRoleConfig.Name,
		logger:     s.logger,
	}, nil
}

func (s *SnowflakeStaticSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: SnowflakeSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/static-creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *SnowflakeStaticSecret) Cleanup(client *api.Client) error {
	return cleanupMount(s.logger, client, s.pathPrefix)
}

func (s *SnowflakeStaticSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     SnowflakeSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SnowflakeStaticSecret) Flags(fs *flag.FlagSet) {}
