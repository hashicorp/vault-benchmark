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
	CassandraSecretTestType   = "cassandra_secret"
	CassandraSecretTestMethod = "GET"
	CassandraDBUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "CASSANDRADB_USERNAME"
	CassandraDBPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "CASSANDRADB_PASSWORD"
)

func init() {
	TestList[CassandraSecretTestType] = func() BenchmarkBuilder { return &CassandraSecret{} }
}

type CassandraSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *CassandraSecretConfig
	logger     hclog.Logger
}

type CassandraSecretConfig struct {
	CassandraDBConfig   *CassandraDBConfig   `hcl:"db_connection,block"`
	CassandraRoleConfig *CassandraRoleConfig `hcl:"role,block"`
}

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

func (c *CassandraSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *CassandraSecretConfig `hcl:"config,block"`
	}{
		Config: &CassandraSecretConfig{
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

func (c *CassandraSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	c.logger = targetLogger.Named(CassandraSecretTestType)

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
	if err := writeStruct(client, filepath.Join(secretPath, "config", c.config.CassandraDBConfig.Name), c.config.CassandraDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", c.config.CassandraRoleConfig.Name), c.config.CassandraRoleConfig); err != nil {
		return nil, err
	}

	return &CassandraSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   c.config.CassandraRoleConfig.Name,
		logger:     c.logger,
	}, nil

}

func (c *CassandraSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CassandraSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *CassandraSecret) Cleanup(client *api.Client) error {
	return cleanupMount(c.logger, client, c.pathPrefix)
}

func (c *CassandraSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CassandraSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CassandraSecret) Flags(fs *flag.FlagSet) {}
