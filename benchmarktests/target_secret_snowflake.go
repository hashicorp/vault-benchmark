// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
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
	// "Register" these tests to the main test registry
	TestList[SnowflakeDynamicSecretTestType] = func() BenchmarkBuilder { return &SnowflakeDynamicSecret{} }
	TestList[SnowflakeStaticSecretTestType] = func() BenchmarkBuilder { return &SnowflakeStaticSecret{} }
}

// Snowflake Dynamic Secret Test Struct
type SnowflakeDynamicSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *SnowflakeDynamicSecretTestConfig
	logger     hclog.Logger
}

// Snowflake Static Secret Test Struct
type SnowflakeStaticSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *SnowflakeStaticSecretTestConfig
	logger     hclog.Logger
}

// Dynamic Secret Config Struct
type SnowflakeDynamicSecretTestConfig struct {
	SnowflakeDBConfig   *SnowflakeDBConfig   `hcl:"db_connection,block"`
	SnowflakeRoleConfig *SnowflakeRoleConfig `hcl:"role,block"`
}

// Static Secret Config Struct
type SnowflakeStaticSecretTestConfig struct {
	SnowflakeDBConfig         *SnowflakeDBConfig         `hcl:"db_connection,block"`
	SnowflakeStaticRoleConfig *SnowflakeStaticRoleConfig `hcl:"static_role,block"`
}

// Snowflake DB Config
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

// Snowflake Role Config (Dynamic)
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

// Snowflake Static Role Config
type SnowflakeStaticRoleConfig struct {
	Name               string `hcl:"name,optional"`
	DBName             string `hcl:"db_name,optional"`
	Username           string `hcl:"username"`
	RotationPeriod     string `hcl:"rotation_period,optional"`
	RotationStatements string `hcl:"rotation_statements,optional"`
	CredentialType     string `hcl:"credential_type,optional"`
	CredentialConfig   string `hcl:"credential_config,optional"`
}

// ===== SnowflakeDynamicSecret Implementation =====

func (s *SnowflakeDynamicSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *SnowflakeDynamicSecretTestConfig `hcl:"config,block"`
	}{
		Config: &SnowflakeDynamicSecretTestConfig{
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

	// Validate required fields
	if s.config.SnowflakeDBConfig.Username == "" {
		return fmt.Errorf("no snowflake username provided but required")
	}

	// Validate authentication method - either password or private key is required
	hasPassword := s.config.SnowflakeDBConfig.Password != ""
	hasPrivateKey := s.config.SnowflakeDBConfig.PrivateKey != ""

	if !hasPassword && !hasPrivateKey {
		return fmt.Errorf("no snowflake password or private key provided but one is required")
	}

	// If using key pair authentication, account is typically required
	if hasPrivateKey && s.config.SnowflakeDBConfig.Account == "" {
		return fmt.Errorf("snowflake account identifier is required when using private key authentication")
	}

	return nil
}

func (s *SnowflakeDynamicSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: SnowflakeSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *SnowflakeDynamicSecret) Cleanup(client *api.Client) error {
	s.logger.Trace(cleanupLogMessage(s.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *SnowflakeDynamicSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     SnowflakeSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SnowflakeDynamicSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	s.logger = targetLogger.Named(SnowflakeDynamicSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	s.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := s.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(s.config.SnowflakeDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("snowflake dynamic db config"), "name", s.config.SnowflakeDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", s.config.SnowflakeDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing snowflake db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(s.config.SnowflakeRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Dynamic Role
	setupLogger.Trace(writingLogMessage("snowflake dynamic role"), "name", s.config.SnowflakeRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", s.config.SnowflakeRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing snowflake dynamic role %q: %v", s.config.SnowflakeRoleConfig.Name, err)
	}

	return &SnowflakeDynamicSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   s.config.SnowflakeRoleConfig.Name,
		logger:     s.logger,
	}, nil
}

func (s *SnowflakeDynamicSecret) Flags(fs *flag.FlagSet) {}

// ===== SnowflakeStaticSecret Implementation =====

func (s *SnowflakeStaticSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *SnowflakeStaticSecretTestConfig `hcl:"config,block"`
	}{
		Config: &SnowflakeStaticSecretTestConfig{
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

	// Validate required fields
	if s.config.SnowflakeDBConfig.Username == "" {
		return fmt.Errorf("no snowflake username provided but required")
	}

	if s.config.SnowflakeStaticRoleConfig.Username == "" {
		return fmt.Errorf("no static role username provided but required")
	}

	// Validate authentication method - either password or private key is required
	hasPassword := s.config.SnowflakeDBConfig.Password != ""
	hasPrivateKey := s.config.SnowflakeDBConfig.PrivateKey != ""

	if !hasPassword && !hasPrivateKey {
		return fmt.Errorf("no snowflake password or private key provided but one is required")
	}

	// If using key pair authentication, account is typically required
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

func (s *SnowflakeStaticSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: SnowflakeSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/static-creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *SnowflakeStaticSecret) Cleanup(client *api.Client) error {
	s.logger.Trace(cleanupLogMessage(s.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *SnowflakeStaticSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     SnowflakeSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SnowflakeStaticSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	s.logger = targetLogger.Named(SnowflakeStaticSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	s.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := s.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(s.config.SnowflakeDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("snowflake static db config"), "name", s.config.SnowflakeDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", s.config.SnowflakeDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing snowflake db config: %v", err)
	}

	// Decode Static Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("static role"))
	staticRoleData, err := structToMap(s.config.SnowflakeStaticRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing static role config from struct: %v", err)
	}

	// Create Static Role
	setupLogger.Trace(writingLogMessage("snowflake static role"), "name", s.config.SnowflakeStaticRoleConfig.Name)
	staticRolePath := filepath.Join(secretPath, "static-roles", s.config.SnowflakeStaticRoleConfig.Name)
	_, err = client.Logical().Write(staticRolePath, staticRoleData)
	if err != nil {
		return nil, fmt.Errorf("error writing snowflake static role %q: %v", s.config.SnowflakeStaticRoleConfig.Name, err)
	}

	return &SnowflakeStaticSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   s.config.SnowflakeStaticRoleConfig.Name,
		logger:     s.logger,
	}, nil
}

func (s *SnowflakeStaticSecret) Flags(fs *flag.FlagSet) {}
