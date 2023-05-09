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
	ElasticSearchSecretTestType   = "elasticsearch_secret"
	ElasticSearchSecretTestMethod = "GET"
	ElasticSearchUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "ELASTICSEARCH_USERNAME"
	ElasticSearchPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "ELASTICSEARCH_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[ElasticSearchSecretTestType] = func() BenchmarkBuilder { return &ElasticSearchTest{} }
}

type ElasticSearchTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *ElasticSearchTestConfig
	logger     hclog.Logger
}

type ElasticSearchTestConfig struct {
	Config *ElasticSearchSecretTestConfig `hcl:"config,block"`
}

type ElasticSearchSecretTestConfig struct {
	ElasticSearchConfig     *ElasticSearchConfig     `hcl:"db_connection,block"`
	ElasticSearchRoleConfig *ElasticSearchRoleConfig `hcl:"role,block"`
}

type ElasticSearchConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnectioon      *bool    `hcl:"verify_connection,optional"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	URL                    string   `hcl:"url"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	CACert                 string   `hcl:"ca_cert,optional"`
	CAPath                 string   `hcl:"ca_path,optional"`
	ClientCert             string   `hcl:"client_cert,optional"`
	ClientKey              string   `hcl:"client_key,optional"`
	TLSServerName          string   `hcl:"tls_server_name,optional"`
	Insecure               bool     `hcl:"insecure,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
	UseOldXPack            bool     `hcl:"use_old_xpack,optional"`
}

type ElasticSearchRoleConfig struct {
	RoleName           string   `hcl:"name,optional"`
	DBName             string   `hcl:"db_name,optional"`
	DefaultTTL         string   `hcl:"default_ttl,optional"`
	MaxTTL             string   `hcl:"max_ttl,optional"`
	CreationStatements []string `hcl:"creation_statements,optional"`
}

func (e *ElasticSearchTest) ParseConfig(body hcl.Body) error {
	e.config = &ElasticSearchTestConfig{
		Config: &ElasticSearchSecretTestConfig{
			ElasticSearchConfig: &ElasticSearchConfig{
				PluginName:   "elasticsearch-database-plugin",
				Name:         "benchmark-elasticsearch",
				AllowedRoles: []string{"benchmark-role"},
				Insecure:     true,
				Username:     os.Getenv(ElasticSearchUsernameEnvVar),
				Password:     os.Getenv(ElasticSearchPasswordEnvVar),
			},
			ElasticSearchRoleConfig: &ElasticSearchRoleConfig{
				DBName:             "benchmark-elasticsearch",
				RoleName:           "benchmark-role",
				CreationStatements: []string{`{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`},
				DefaultTTL:         "1h",
				MaxTTL:             "24h",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, e.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	if e.config.Config.ElasticSearchConfig.Username == "" {
		return fmt.Errorf("no elasticsearch username provided but required")
	}

	if e.config.Config.ElasticSearchConfig.Password == "" {
		return fmt.Errorf("no elasticsearch password provided but required")
	}

	return nil
}

func (e *ElasticSearchTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: ElasticSearchSecretTestMethod,
		URL:    client.Address() + e.pathPrefix + "/creds/" + e.roleName,
		Header: e.header,
	}
}

func (e *ElasticSearchTest) Cleanup(client *api.Client) error {
	e.logger.Trace(cleanupLogMessage(e.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(e.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (e *ElasticSearchTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     ElasticSearchSecretTestMethod,
		pathPrefix: e.pathPrefix,
	}
}

func (e *ElasticSearchTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := e.config.Config
	e.logger = targetLogger.Named(ElasticSearchSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	e.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting database secrets engine: %v", err)
	}

	setupLogger := e.logger.Named(secretPath)

	// Decode DB Config
	setupLogger.Trace(parsingConfigLogMessage("db"))
	elasticSearchConfigData, err := structToMap(config.ElasticSearchConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing elasticsearch config from struct: %v", err)
	}

	// Write DB config
	setupLogger.Trace(writingLogMessage("elasticsearch db config"), "name", config.ElasticSearchConfig.Name)
	dbPath := filepath.Join(secretPath, "config", config.ElasticSearchConfig.Name)
	_, err = client.Logical().Write(dbPath, elasticSearchConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing Elasticsearch db config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	elasticSearchRoleConfigData, err := structToMap(config.ElasticSearchRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("elasticsearc role"), "name", config.ElasticSearchRoleConfig.RoleName)
	rolePath := filepath.Join(secretPath, "roles", config.ElasticSearchRoleConfig.RoleName)
	_, err = client.Logical().Write(rolePath, elasticSearchRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing elasticsearch role %q: %v", config.ElasticSearchRoleConfig.RoleName, err)
	}

	return &ElasticSearchTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.ElasticSearchRoleConfig.RoleName,
		logger:     e.logger,
	}, nil
}

func (e *ElasticSearchTest) Flags(fs *flag.FlagSet) {}
