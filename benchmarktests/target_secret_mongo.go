// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	MongoDBSecretTestType   = "mongodb_secret"
	MongoDBSecretTestMethod = "GET"
	MongoDBUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "MONGODB_USERNAME"
	MongoDBPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "MONGODB_PASSWORD"
)

func init() {
	TestList[MongoDBSecretTestType] = func() BenchmarkBuilder { return &MongoDBSecret{} }
}

type MongoDBSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *MongoDBSecretConfig
	logger     hclog.Logger
}

type MongoDBSecretConfig struct {
	MongoDBConfig     *MongoDBConfig     `hcl:"db_connection,block"`
	MongoDBRoleConfig *MongoDBRoleConfig `hcl:"role,block"`
}

type MongoDBConfig struct {
	Name              string   `hcl:"name,optional"`
	PluginName        string   `hcl:"plugin_name,optional"`
	PluginVersion     string   `hcl:"plugin_version,optional"`
	VerifyConnection  *bool    `hcl:"verify_connection"`
	AllowedRoles      []string `hcl:"allowed_roles,optional"`
	ConnectionURL     string   `hcl:"connection_url"`
	WriteConcern      string   `hcl:"write_concern,optional"`
	Username          string   `hcl:"username,optional"`
	Password          string   `hcl:"password,optional"`
	TLSCertificateKey string   `hcl:"tls_certificate_key,optional"`
	TLSCA             string   `hcl:"tls_ca,optional"`
	UsernameTemplate  string   `hcl:"username_template,optional"`
}

type MongoDBRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements,optional"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
}

func (m *MongoDBSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *MongoDBSecretConfig `hcl:"config,block"`
	}{
		Config: &MongoDBSecretConfig{
			MongoDBConfig: &MongoDBConfig{
				Name:         "benchmark-mongo",
				PluginName:   "mongodb-database-plugin",
				AllowedRoles: []string{"benchmark-role"},
				Username:     os.Getenv(MongoDBUsernameEnvVar),
				Password:     os.Getenv(MongoDBPasswordEnvVar),
			},
			MongoDBRoleConfig: &MongoDBRoleConfig{
				Name:               "benchmark-role",
				DBName:             "benchmark-mongo",
				DefaultTTL:         "1h",
				MaxTTL:             "24h",
				CreationStatements: `{"db": "admin", "roles": [{ "role": "readWrite" }, {"role": "read", "db": "foo"}] }`,
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	m.config = testConfig.Config

	if m.config.MongoDBConfig.Username == "" {
		return fmt.Errorf("no mongodb username provided but required")
	}

	if m.config.MongoDBConfig.Password == "" {
		return fmt.Errorf("no mongodb password provided but required")
	}

	return nil
}

func (m *MongoDBSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	m.logger = targetLogger.Named(MongoDBSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	m.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := m.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, secretPath+"/config/"+m.config.MongoDBConfig.Name, m.config.MongoDBConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roles/"+m.config.MongoDBRoleConfig.Name, m.config.MongoDBRoleConfig); err != nil {
		return nil, err
	}

	return &MongoDBSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   m.config.MongoDBRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *MongoDBSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: MongoDBSecretTestMethod,
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MongoDBSecret) Cleanup(client *api.Client) error {
	return cleanupMount(m.logger, client, m.pathPrefix)
}

func (m *MongoDBSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MongoDBSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MongoDBSecret) Flags(fs *flag.FlagSet) {}
