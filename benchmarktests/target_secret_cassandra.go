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
	"github.com/hashicorp/hcl/v2"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	CassandraSecretTestType   = "cassandra_secret"
	CassandraSecretTestMethod = "GET"
	CassandraDBUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "CASSANDRADB_USERNAME"
	CassandraDBPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "CASSANDRADB_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[CassandraSecretTestType] = func() BenchmarkBuilder { return &CassandraSecret{} }
}

// Cassandra Secret Test Struct
type CassandraSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *CassandraSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type CassandraSecretTestConfig struct {
	CassandraDBConfig   *CassandraDBConfig   `hcl:"db_connection,block"`
	CassandraRoleConfig *CassandraRoleConfig `hcl:"role,block"`
}

// Cassandra DB Config
type CassandraDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	Hosts                  string   `hcl:"hosts"`
	Port                   int      `hcl:"port,optional"`
	ProtocolVersion        int      `hcl:"protocol_version"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	TLS                    *bool    `hcl:"tls,optional"`
	InsecureTLS            bool     `hcl:"insecure_tls,optional"`
	PEMBundle              string   `hcl:"pem_bundle,optional"`
	TLSServerName          string   `hcl:"tls_server_name,optional"`
	PEMhcl                 string   `hcl:"pem_hcl,optional"`
	SkipVerification       bool     `hcl:"skip_verification,optional"`
	ConnectTimeout         string   `hcl:"connect_timeout,optional"`
	LocalDatacenter        string   `hcl:"local_datacenter,optional"`
	SocketKeepAlive        string   `hcl:"socket_keep_alive,optional"`
	Consistency            string   `hcl:"consistency,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
}

// Cassandra Role Config
type CassandraRoleConfig struct {
	Name                   string   `hcl:"name,optional"`
	DBName                 string   `hcl:"db_name,optional"`
	DefaultTTL             string   `hcl:"default_ttl,optional"`
	MaxTTL                 string   `hcl:"max_ttl,optional"`
	CreationStatements     []string `hcl:"creation_statements"`
	RevocationStatements   []string `hcl:"revocation_statements,optional"`
	RollbackStatements     []string `hcl:"rollback_statements,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (c *CassandraSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *CassandraSecretTestConfig `hcl:"config,block"`
	}{
		Config: &CassandraSecretTestConfig{
			CassandraDBConfig: &CassandraDBConfig{
				Name:         "benchmark-cassandra",
				PluginName:   "cassandra-database-plugin",
				AllowedRoles: []string{"benchmark-role"},
				Port:         9042,
				Username:     os.Getenv(CassandraDBUsernameEnvVar),
				Password:     os.Getenv(CassandraDBPasswordEnvVar),
			},
			CassandraRoleConfig: &CassandraRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-cassandra",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config

	if c.config.CassandraDBConfig.Username == "" {
		return fmt.Errorf("no cassandradb username provided but required")
	}

	if c.config.CassandraDBConfig.Password == "" {
		return fmt.Errorf("no cassandradb password provided but required")
	}

	return nil
}

func (c *CassandraSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CassandraSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *CassandraSecret) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (c *CassandraSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CassandraSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CassandraSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	c.logger = targetLogger.Named(CassandraSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	c.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = topLevelConfig.Client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting database secrets engine: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(c.config.CassandraDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("cassandra db config"), "name", c.config.CassandraDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", c.config.CassandraDBConfig.Name)
	_, err = topLevelConfig.Client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing cassandra db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(c.config.CassandraRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Set Up Role
	setupLogger.Trace(writingLogMessage("role"), "name", c.config.CassandraRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", c.config.CassandraRoleConfig.Name)
	_, err = topLevelConfig.Client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing cassandra role %q: %v", c.config.CassandraRoleConfig.Name, err)
	}

	return &CassandraSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(topLevelConfig.Client),
		roleName:   c.config.CassandraRoleConfig.Name,
	}, nil

}

func (c *CassandraSecret) Flags(fs *flag.FlagSet) {}
