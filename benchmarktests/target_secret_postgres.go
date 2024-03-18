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
	PostgreSQLSecretTestType   = "postgresql_secret"
	PostgreSQLSecretTestMethod = "GET"
	PostgreSQLUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "POSTGRES_USERNAME"
	PostgreSQLPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "POSTGRES_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[PostgreSQLSecretTestType] = func() BenchmarkBuilder { return &PostgreSQLSecret{} }
}

// Postgres Secret Test Struct
type PostgreSQLSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *PostgreSQLSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type PostgreSQLSecretTestConfig struct {
	PostgreSQLDBConfig   *PostgreSQLDBConfig   `hcl:"db_connection,block"`
	PostgreSQLRoleConfig *PostgreSQLRoleConfig `hcl:"role,block"`
}

// PostgreSQL DB Config
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

// PostgreSQL Role Config
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

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (s *PostgreSQLSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *PostgreSQLSecretTestConfig `hcl:"config,block"`
	}{
		Config: &PostgreSQLSecretTestConfig{
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

func (s *PostgreSQLSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: PostgreSQLSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *PostgreSQLSecret) Cleanup(client *api.Client) error {
	s.logger.Trace(cleanupLogMessage(s.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *PostgreSQLSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     PostgreSQLSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *PostgreSQLSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	s.logger = targetLogger.Named(PostgreSQLSecretTestType)

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
	dbData, err := structToMap(s.config.PostgreSQLDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("postgres db config"), "name", s.config.PostgreSQLDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", s.config.PostgreSQLDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing postgresql db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(s.config.PostgreSQLRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("postgres role"), "name", s.config.PostgreSQLRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", s.config.PostgreSQLRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing postgresql role %q: %v", s.config.PostgreSQLRoleConfig.Name, err)
	}

	return &PostgreSQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   s.config.PostgreSQLRoleConfig.Name,
		logger:     s.logger,
	}, nil

}

func (l *PostgreSQLSecret) Flags(fs *flag.FlagSet) {}
