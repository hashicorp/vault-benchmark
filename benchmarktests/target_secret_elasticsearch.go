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
	ElasticSearchSecretTestType   = "elasticsearch_secret"
	ElasticSearchSecretTestMethod = "GET"
	ElasticSearchUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "ELASTICSEARCH_USERNAME"
	ElasticSearchPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "ELASTICSEARCH_PASSWORD"
)

func init() {
	TestList[ElasticSearchSecretTestType] = func() BenchmarkBuilder { return &ElasticSearchSecret{} }
}

type ElasticSearchSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *ElasticSearchSecretConfig
	logger     hclog.Logger
}

type ElasticSearchSecretConfig struct {
	ElasticSearchConfig     *ElasticSearchConfig     `hcl:"db_connection,block"`
	ElasticSearchRoleConfig *ElasticSearchRoleConfig `hcl:"role,block"`
}

type ElasticSearchConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection,optional"`
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

func (e *ElasticSearchSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *ElasticSearchSecretConfig `hcl:"config,block"`
	}{
		Config: &ElasticSearchSecretConfig{
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

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	e.config = testConfig.Config

	if e.config.ElasticSearchConfig.Username == "" {
		return fmt.Errorf("no elasticsearch username provided but required")
	}

	if e.config.ElasticSearchConfig.Password == "" {
		return fmt.Errorf("no elasticsearch password provided but required")
	}

	return nil
}

func (e *ElasticSearchSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	e.logger = targetLogger.Named(ElasticSearchSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	e.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting database secrets engine: %v", err)
	}

	setupLogger := e.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("db"))
	if err := writeStruct(client, filepath.Join(secretPath, "config", e.config.ElasticSearchConfig.Name), e.config.ElasticSearchConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(secretPath, "roles", e.config.ElasticSearchRoleConfig.RoleName), e.config.ElasticSearchRoleConfig); err != nil {
		return nil, err
	}

	return &ElasticSearchSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   e.config.ElasticSearchRoleConfig.RoleName,
		logger:     e.logger,
	}, nil
}

func (e *ElasticSearchSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: ElasticSearchSecretTestMethod,
		URL:    client.Address() + e.pathPrefix + "/creds/" + e.roleName,
		Header: e.header,
	}
}

func (e *ElasticSearchSecret) Cleanup(client *api.Client) error {
	return cleanupMount(e.logger, client, e.pathPrefix)
}

func (e *ElasticSearchSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     ElasticSearchSecretTestMethod,
		pathPrefix: e.pathPrefix,
	}
}

func (e *ElasticSearchSecret) Flags(fs *flag.FlagSet) {}
