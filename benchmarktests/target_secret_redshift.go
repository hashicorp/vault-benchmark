// Copyright IBM Corp. 2022, 2025
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
	RedshiftSecretTestType   = "redshift_secret"
	RedshiftSecretTestMethod = "GET"
	RedshiftUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "REDSHIFT_USERNAME"
	RedshiftPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "REDSHIFT_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[RedshiftSecretTestType] = func() BenchmarkBuilder { return &RedshiftSecret{} }
}

// Redshift Secret Test Struct
type RedshiftSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *RedshiftSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type RedshiftSecretTestConfig struct {
	RedshiftDBConfig   *RedshiftDBConfig   `hcl:"db_connection,block"`
	RedshiftRoleConfig *RedshiftRoleConfig `hcl:"role,block"`
}

// Redshift DB Config
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

// Redshift Role Config
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

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (r *RedshiftSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *RedshiftSecretTestConfig `hcl:"config,block"`
	}{
		Config: &RedshiftSecretTestConfig{
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

func (r *RedshiftSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedshiftSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *RedshiftSecret) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *RedshiftSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedshiftSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RedshiftSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RedshiftSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	r.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(r.config.RedshiftDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("redshift db config"), "name", r.config.RedshiftDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", r.config.RedshiftDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing redshift db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(r.config.RedshiftRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("redshift role"), "name", r.config.RedshiftRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", r.config.RedshiftRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing redshift role %q: %v", r.config.RedshiftRoleConfig.Name, err)
	}

	return &RedshiftSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RedshiftRoleConfig.Name,
		logger:     r.logger,
	}, nil
}

func (r *RedshiftSecret) Flags(fs *flag.FlagSet) {}
