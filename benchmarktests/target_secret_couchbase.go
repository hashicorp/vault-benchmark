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
	CouchbaseSecretTestType   = "couchbase_secret"
	CouchbaseSecretTestMethod = "GET"
	CouchbaseUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "COUCHBASE_USERNAME"
	CouchbasePasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "COUCHBASE_PASSWORD"
)

func init() {
	TestList[CouchbaseSecretTestType] = func() BenchmarkBuilder { return &CouchbaseSecret{} }
}

type CouchbaseSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *CouchbaseSecretConfig
	logger     hclog.Logger
}

type CouchbaseSecretConfig struct {
	DBConfig   *CouchbaseConfig     `hcl:"db_connection,block"`
	RoleConfig *CouchbaseRoleConfig `hcl:"role,block"`
}

type CouchbaseConfig struct {
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	PluginVersion    string   `hcl:"plugin_version,optional"`
	VerifyConnection *bool    `hcl:"verify_connection,optional"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`
	PasswordPolicy   string   `hcl:"password_policy,optional"`
	Username         string   `hcl:"username,optional"`
	Password         string   `hcl:"password,optional"`
	DisableEscaping  bool     `hcl:"disable_escaping,optional"`

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

func (c *CouchbaseSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *CouchbaseSecretConfig `hcl:"config,block"`
	}{
		Config: &CouchbaseSecretConfig{
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

func (c *CouchbaseSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	c.logger = targetLogger.Named(CouchbaseSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	c.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting database secrets engine: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, filepath.Join(secretPath, "config", c.config.DBConfig.Name), c.config.DBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", c.config.RoleConfig.Name), c.config.RoleConfig); err != nil {
		return nil, err
	}

	return &CouchbaseSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   c.config.RoleConfig.Name,
		logger:     c.logger,
	}, nil
}

func (c *CouchbaseSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CouchbaseSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *CouchbaseSecret) Cleanup(client *api.Client) error {
	return cleanupMount(c.logger, client, c.pathPrefix)
}

func (c *CouchbaseSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CouchbaseSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CouchbaseSecret) Flags(fs *flag.FlagSet) {}
