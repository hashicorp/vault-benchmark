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
	MongoDBAtlasSecretTestType   = "mongodb_atlas_secret"
	MongoDBAtlasSecretTestMethod = "GET"
	MongoDBAtlasPublicKey        = VaultBenchmarkEnvVarPrefix + "MONGODB_ATLAS_PUBLIC_KEY"
	MongoDBAtlasPrivateKey       = VaultBenchmarkEnvVarPrefix + "MONGODB_ATLAS_PRIVATE_KEY"
)

func init() {
	TestList[MongoDBAtlasSecretTestType] = func() BenchmarkBuilder { return &MongoDBAtlasSecret{} }
}

type MongoDBAtlasSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *MongoDBAtlasSecretConfig
	logger     hclog.Logger
}

type MongoDBAtlasSecretConfig struct {
	MongoDBAtlasConfig     *MongoDBAtlasConfig     `hcl:"db_connection,block"`
	MongoDBAtlasRoleConfig *MongoDBAtlasRoleConfig `hcl:"role,block"`
}

type MongoDBAtlasConfig struct {
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	PluginVersion    string   `hcl:"plugin_version,optional"`
	VerifyConnection *bool    `hcl:"verify_connection"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`
	PublicKey        string   `hcl:"public_key,optional"`
	PrivateKey       string   `hcl:"private_key,optional"`
	ProjectID        string   `hcl:"project_id,optional"`
	UsernameTemplate string   `hcl:"username_template,optional"`
}

type MongoDBAtlasRoleConfig struct {
	Name               string `hcl:"name,optional"`
	DBName             string `hcl:"db_name,optional"`
	DefaultTTL         string `hcl:"default_ttl,optional"`
	MaxTTL             string `hcl:"max_ttl,optional"`
	CreationStatements string `hcl:"creation_statements,optional"`
}

func (m *MongoDBAtlasSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *MongoDBAtlasSecretConfig `hcl:"config,block"`
	}{
		Config: &MongoDBAtlasSecretConfig{
			MongoDBAtlasConfig: &MongoDBAtlasConfig{
				Name:         "benchmark-mongodb-atlas",
				PluginName:   "mongodbatlas-database-plugin",
				AllowedRoles: []string{"benchmark-role"},
				PublicKey:    os.Getenv(MongoDBAtlasPublicKey),
				PrivateKey:   os.Getenv(MongoDBAtlasPrivateKey),
			},
			MongoDBAtlasRoleConfig: &MongoDBAtlasRoleConfig{
				Name:               "benchmark-role",
				DBName:             "benchmark-mongodb-atlas",
				DefaultTTL:         "1h",
				MaxTTL:             "24h",
				CreationStatements: `{"database_name": "admin","roles": [{"databaseName":"admin","roleName":"atlasAdmin"}]}`,
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	m.config = testConfig.Config

	if m.config.MongoDBAtlasConfig.PublicKey == "" {
		return fmt.Errorf("no mongodb_atlas PublicKey provided but required")
	}

	if m.config.MongoDBAtlasConfig.PrivateKey == "" {
		return fmt.Errorf("no mongodb_atlas PrivateKey provided but required")
	}

	return nil
}

func (m *MongoDBAtlasSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	m.logger = targetLogger.Named(MongoDBAtlasSecretTestType)

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
	if err := writeStruct(client, secretPath+"/config/"+m.config.MongoDBAtlasConfig.Name, m.config.MongoDBAtlasConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roles/"+m.config.MongoDBAtlasRoleConfig.Name, m.config.MongoDBAtlasRoleConfig); err != nil {
		return nil, err
	}

	return &MongoDBAtlasSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   m.config.MongoDBAtlasRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *MongoDBAtlasSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: MongoDBAtlasSecretTestMethod,
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MongoDBAtlasSecret) Cleanup(client *api.Client) error {
	return cleanupMount(m.logger, client, m.pathPrefix)
}

func (m *MongoDBAtlasSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MongoDBAtlasSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MongoDBAtlasSecret) Flags(fs *flag.FlagSet) {}
