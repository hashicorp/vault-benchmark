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
	OracleSecretTestType   = "oracle_secret"
	OracleSecretTestMethod = "GET"
	OracleUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "ORACLE_USERNAME"
	OraclePasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "ORACLE_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[OracleSecretTestType] = func() BenchmarkBuilder { return &OracleSecret{} }
}

// Oracle Secret Test Struct
type OracleSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *OracleSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type OracleSecretTestConfig struct {
	OracleDBConfig   *OracleDBConfig   `hcl:"db_connection,block"`
	OracleRoleConfig *OracleRoleConfig `hcl:"role,block"`
}

// Oracle DB Config
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
	// Oracle-specific configurations
	SplitStatements    bool `hcl:"split_statements,optional"`
	DisconnectSessions bool `hcl:"disconnect_sessions,optional"`
}

// Oracle Role Config
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

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (o *OracleSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *OracleSecretTestConfig `hcl:"config,block"`
	}{
		Config: &OracleSecretTestConfig{
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
				CreationStatements:   "CREATE USER {{username}} IDENTIFIED BY \"{{password}}\"; GRANT CONNECT TO {{username}}; GRANT CREATE SESSION TO {{username}};",
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

	return nil
}

func (o *OracleSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: OracleSecretTestMethod,
		URL:    client.Address() + o.pathPrefix + "/creds/" + o.roleName,
		Header: o.header,
	}
}

func (o *OracleSecret) Cleanup(client *api.Client) error {
	o.logger.Trace(cleanupLogMessage(o.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(o.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (o *OracleSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     OracleSecretTestMethod,
		pathPrefix: o.pathPrefix,
	}
}

func (o *OracleSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	o.logger = targetLogger.Named(OracleSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	o.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := o.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(o.config.OracleDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("oracle db config"), "name", o.config.OracleDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", o.config.OracleDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing oracle db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(o.config.OracleRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("oracle role"), "name", o.config.OracleRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", o.config.OracleRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing oracle role %q: %v", o.config.OracleRoleConfig.Name, err)
	}

	return &OracleSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   o.config.OracleRoleConfig.Name,
		logger:     o.logger,
	}, nil
}

func (o *OracleSecret) Flags(fs *flag.FlagSet) {}
