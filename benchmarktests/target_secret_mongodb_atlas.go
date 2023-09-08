// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
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
	// "Register" this test to the main test registry
	TestList[MongoDBAtlasSecretTestType] = func() BenchmarkBuilder { return &MongoDBAtlasTest{} }
}

type MongoDBAtlasTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *MongoDBAtlasSecretTestConfig
	logger     hclog.Logger
}

type MongoDBAtlasSecretTestConfig struct {
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

func (m *MongoDBAtlasTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *MongoDBAtlasSecretTestConfig `hcl:"config,block"`
	}{
		Config: &MongoDBAtlasSecretTestConfig{
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

	// Ensure that the username and password are set
	if m.config.MongoDBAtlasConfig.PublicKey == "" {
		return fmt.Errorf("no mongodb_atlas PublicKey provided but required")
	}

	if m.config.MongoDBAtlasConfig.PrivateKey == "" {
		return fmt.Errorf("no mongodb_atlas PrivateKey provided but required")
	}

	return nil
}

func (m *MongoDBAtlasTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MongoDBAtlasTest) Cleanup(client *api.Client) error {
	m.logger.Trace(cleanupLogMessage(m.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(m.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (m *MongoDBAtlasTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MongoDBAtlasSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MongoDBAtlasTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	m.logger = targetLogger.Named(MongoDBAtlasSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	m.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := m.logger.Named(secretPath)

	// Decode DB Config
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbConfigData, err := structToMap(m.config.MongoDBAtlasConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding mongodb_atlas config from struct: %v", err)
	}

	// Write DB config
	setupLogger.Trace(writingLogMessage("mongodb_atlas config"), "name", m.config.MongoDBAtlasConfig.Name)
	_, err = client.Logical().Write(secretPath+"/config/"+m.config.MongoDBAtlasConfig.Name, dbConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleConfigData, err := structToMap(m.config.MongoDBAtlasRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("mongodb_atlas role"), "name", m.config.MongoDBAtlasRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+m.config.MongoDBAtlasRoleConfig.Name, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing mongodb_atlas role %q: %v", m.config.MongoDBAtlasRoleConfig.Name, err)
	}

	return &MongoDBAtlasTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   m.config.MongoDBAtlasRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *MongoDBAtlasTest) Flags(fs *flag.FlagSet) {}
