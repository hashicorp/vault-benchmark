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

const (
	CouchbaseSecretTestType   = "couchbase_secret"
	CouchbaseSecretTestMethod = "GET"
	CouchbaseUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "COUCHBASE_USERNAME"
	CouchbasePasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "COUCHBASE_PASSWORD"
)

func init() {
	TestList[CouchbaseSecretTestType] = func() BenchmarkBuilder { return &CouchbaseSecretTest{} }
}

type CouchbaseSecretTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *CouchbaseSecretTestConfig
	logger     hclog.Logger
}

type CouchbaseSecretTestConfig struct {
	DBConfig   *CouchbaseConfig     `hcl:"db_connection,block"`
	RoleConfig *CouchbaseRoleConfig `hcl:"role,block"`
}

type CouchbaseConfig struct {
	// Common
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	PluginVersion    string   `hcl:"plugin_version,optional"`
	VerifyConnection *bool    `hcl:"verify_connection,optional"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`
	PasswordPolicy   string   `hcl:"password_policy,optional"`
	Username         string   `hcl:"username,optional"`
	Password         string   `hcl:"password,optional"`
	DisableEscaping  bool     `hcl:"disable_escaping,optional"`

	// Couchbase Specific
	Hosts            string `hcl:"hosts"`
	TLS              bool   `hcl:"tls,optional"`
	InsecureTLS      bool   `hcl:"insecure_tls,optional"`
	UsernameTemplate string `hcl:"username_template,optional"`
	Base64PEM        string `hcl:"base64pem,optional"`
	BucketName       string `hcl:"bucket_name"`
}

type CouchbaseRoleConfig struct {
	Name               string   `hcl:"name,optional"`
	DBName             string   `hcl:"db_name,optional"`
	DefaultTTL         string   `hcl:"default_ttl,optional"`
	MaxTTL             string   `hcl:"max_ttl,optional"`
	CreationStatements []string `hcl:"creation_statements,optional"`
}

func (c *CouchbaseSecretTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *CouchbaseSecretTestConfig `hcl:"config,block"`
	}{
		Config: &CouchbaseSecretTestConfig{
			DBConfig: &CouchbaseConfig{
				Name:       "benchmark-database",
				PluginName: "couchbase-database-plugin",
				AllowedRoles: []string{
					"benchmark-role",
				},
				TLS:      false,
				Username: os.Getenv(CouchbaseUsernameEnvVar),
				Password: os.Getenv(CouchbasePasswordEnvVar),
			},
			RoleConfig: &CouchbaseRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-database",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config

	if c.config.DBConfig.Username == "" {
		return fmt.Errorf("no couchbase username provided but required")
	}

	if c.config.DBConfig.Password == "" {
		return fmt.Errorf("no couchbase password provided but required")
	}

	return nil
}

func (c *CouchbaseSecretTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CouchbaseSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *CouchbaseSecretTest) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (c *CouchbaseSecretTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CouchbaseSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CouchbaseSecretTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	c.logger = targetLogger.Named(CouchbaseSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	c.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting database secrets engine: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(c.config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Write Config
	setupLogger.Trace(writingLogMessage("couchbase db config"), "name", c.config.DBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", c.config.DBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing couchbase db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(c.config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("couchbase role"), "name", c.config.RoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", c.config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing couchbase role %q: %v", c.config.RoleConfig.Name, err)
	}

	return &CouchbaseSecretTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   c.config.RoleConfig.Name,
		logger:     c.logger,
	}, nil
}

func (c *CouchbaseSecretTest) Flags(fs *flag.FlagSet) {}
