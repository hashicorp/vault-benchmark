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
	InfluxDBSecretTestType   = "influxdb_secret"
	InfluxDBSecretTestMethod = "GET"
	InfluxDBUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "INFLUXDB_USERNAME"
	InfluxDBPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "INFLUXDB_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[InfluxDBSecretTestType] = func() BenchmarkBuilder { return &InfluxDBSecret{} }
}

// InfluxDB Secret Test Struct
type InfluxDBSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *InfluxDBSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type InfluxDBSecretTestConfig struct {
	InfluxDBDBConfig   *InfluxDBDBConfig   `hcl:"db_connection,block"`
	InfluxDBRoleConfig *InfluxDBRoleConfig `hcl:"role,block"`
}

// InfluxDB DB Config
type InfluxDBDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection,optional"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	Host                   string   `hcl:"host,optional"`
	Port                   int      `hcl:"port,optional"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	TLS                    bool     `hcl:"tls,optional"`
	InsecureTLS            bool     `hcl:"insecure_tls,optional"`
	ConnectTimeout         string   `hcl:"connect_timeout,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
}

// InfluxDB Role Config
type InfluxDBRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
	RollbackStatements   string `hcl:"rollback_statements,optional"`
	RenewStatements      string `hcl:"renew_statements,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (i *InfluxDBSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *InfluxDBSecretTestConfig `hcl:"config,block"`
	}{
		Config: &InfluxDBSecretTestConfig{
			InfluxDBDBConfig: &InfluxDBDBConfig{
				Name:         "benchmark-influxdb",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "influxdb-database-plugin",
				Username:     os.Getenv(InfluxDBUsernameEnvVar),
				Password:     os.Getenv(InfluxDBPasswordEnvVar),
			},
			InfluxDBRoleConfig: &InfluxDBRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-influxdb",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	i.config = testConfig.Config

	if i.config.InfluxDBDBConfig.Username == "" {
		return fmt.Errorf("no influxdb username provided but required")
	}

	if i.config.InfluxDBDBConfig.Password == "" {
		return fmt.Errorf("no influxdb password provided but required")
	}

	return nil
}

func (i *InfluxDBSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: InfluxDBSecretTestMethod,
		URL:    client.Address() + i.pathPrefix + "/creds/" + i.roleName,
		Header: i.header,
	}
}

func (i *InfluxDBSecret) Cleanup(client *api.Client) error {
	i.logger.Trace(cleanupLogMessage(i.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(i.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (i *InfluxDBSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     InfluxDBSecretTestMethod,
		pathPrefix: i.pathPrefix,
	}
}

func (i *InfluxDBSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	i.logger = targetLogger.Named(InfluxDBSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	i.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := i.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(i.config.InfluxDBDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("influxdb db config"), "name", i.config.InfluxDBDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", i.config.InfluxDBDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing influxdb db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(i.config.InfluxDBRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("influxdb role"), "name", i.config.InfluxDBRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", i.config.InfluxDBRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing influxdb role %q: %v", i.config.InfluxDBRoleConfig.Name, err)
	}

	return &InfluxDBSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   i.config.InfluxDBRoleConfig.Name,
		logger:     i.logger,
	}, nil

}

func (i *InfluxDBSecret) Flags(fs *flag.FlagSet) {}
