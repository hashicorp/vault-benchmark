package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

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
)

func init() {
	// "Register" this test to the main test registry
	TestList[ElasticSearchSecretTestType] = func() BenchmarkBuilder { return &ElasticSearchTest{} }
}

type ElasticSearchTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
	config     *ElasticSearchTestConfig
}

type ElasticSearchTestConfig struct {
	Config *ElasticSearchSecretTestConfig `hcl:"config,block"`
}

type ElasticSearchSecretTestConfig struct {
	ElasticSearchConfig     *ElasticSearchConfig     `hcl:"db_config,block"`
	ElasticSearchRoleConfig *ElasticSearchRoleConfig `hcl:"role_config,block"`
}

type ElasticSearchConfig struct {
	DBName       string `hcl:"name,optional"`
	PluginName   string `hcl:"plugin_name,optional"`
	AllowedRoles string `hcl:"allowed_roles,optional"`
	URL          string `hcl:"url"`
	Username     string `hcl:"username"`
	Password     string `hcl:"password"`
	Insecure     bool   `hcl:"insecure,optional"`
	CACert       string `hcl:"ca_cert,optional"`
	ClientCert   string `hcl:"client_cert,optional"`
	ClientKey    string `hcl:"client_key,optional"`
}

type ElasticSearchRoleConfig struct {
	RoleName           string `hcl:"name,optional"`
	DBName             string `hcl:"db_name,optional"`
	DefaultTTL         string `hcl:"default_ttl,optional"`
	MaxTTL             string `hcl:"max_ttl,optional"`
	CreationStatements string `hcl:"creation_statements,optional"`
}

func (e *ElasticSearchTest) ParseConfig(body hcl.Body) error {
	e.config = &ElasticSearchTestConfig{
		Config: &ElasticSearchSecretTestConfig{
			ElasticSearchConfig: &ElasticSearchConfig{
				PluginName:   "elasticsearch-database-plugin",
				DBName:       "es-benchmark",
				AllowedRoles: "internally-defined-role",
				Insecure:     true,
			},
			ElasticSearchRoleConfig: &ElasticSearchRoleConfig{
				DBName:             "es-benchmark",
				RoleName:           "internally-defined-role",
				CreationStatements: `{"elasticsearch_role_definition": {"indices": [{"names":["*"], "privileges":["read"]}]}}`,
				DefaultTTL:         "1h",
				MaxTTL:             "24h",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, e.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	return nil
}

func (e *ElasticSearchTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + e.pathPrefix + "/creds/" + e.roleName,
		Header: e.header,
	}
}

func (e *ElasticSearchTest) Cleanup(client *api.Client) error {
	client.SetClientTimeout(e.timeout)

	_, err := client.Logical().Delete(strings.Replace(e.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (e *ElasticSearchTest) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     ElasticSearchSecretTestMethod,
		pathPrefix: e.pathPrefix,
	}
	return tInfo
}

func (e *ElasticSearchTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := e.config.Config

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Decode DB Config
	elasticSearchConfigData, err := structToMap(config.ElasticSearchConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding ElasticSearch config from struct: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(secretPath+"/config/"+config.ElasticSearchConfig.DBName, elasticSearchConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing Elasticsearch db config: %v", err)
	}

	// Decode Role Config
	elasticSearchRoleConfigData, err := structToMap(config.ElasticSearchRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding ElasticSearch Role config from struct: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(secretPath+"/roles/"+config.ElasticSearchRoleConfig.RoleName, elasticSearchRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing Elasticsearch db role: %v", err)
	}

	return &ElasticSearchTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.ElasticSearchRoleConfig.RoleName,
	}, nil
}

func (e *ElasticSearchTest) Flags(fs *flag.FlagSet) {}
