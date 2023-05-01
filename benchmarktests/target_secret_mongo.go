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
	MongoDBSecretTestType   = "mongodb_secret"
	MongoDBSecretTestMethod = "GET"
	MongoDBUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "MONGODB_USERNAME"
	MongoDBPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "MONGODB_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[MongoDBSecretTestType] = func() BenchmarkBuilder { return &MongoDBTest{} }
}

type MongoDBTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *MongoDBTestConfig
	logger     hclog.Logger
}

type MongoDBTestConfig struct {
	Config *MongoDBSecretTestConfig `hcl:"config,block"`
}

type MongoDBSecretTestConfig struct {
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

func (m *MongoDBTest) ParseConfig(body hcl.Body) error {
	m.config = &MongoDBTestConfig{
		Config: &MongoDBSecretTestConfig{
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

	diags := gohcl.DecodeBody(body, nil, m.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Ensure that the username and password are set
	if m.config.Config.MongoDBConfig.Username == "" {
		return fmt.Errorf("no mongodb username provided but required")
	}

	if m.config.Config.MongoDBConfig.Password == "" {
		return fmt.Errorf("no mongodb password provided but required")
	}

	return nil
}

func (m *MongoDBTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MongoDBTest) Cleanup(client *api.Client) error {
	m.logger.Trace(cleanupLogMessage(m.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(m.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (m *MongoDBTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MongoDBSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MongoDBTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := m.config.Config
	m.logger = targetLogger.Named(MongoDBSecretTestType)

	if randomMountName {
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
	dbConfigData, err := structToMap(config.MongoDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding mongodb config from struct: %v", err)
	}

	// Write DB config
	setupLogger.Trace(writingLogMessage("mongodb config"), "name", config.MongoDBConfig.Name)
	_, err = client.Logical().Write(secretPath+"/config/"+config.MongoDBConfig.Name, dbConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleConfigData, err := structToMap(config.MongoDBRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("mongodb role"), "name", config.MongoDBRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+config.MongoDBRoleConfig.Name, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing mongodb role %q: %v", config.MongoDBRoleConfig.Name, err)
	}

	return &MongoDBTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.MongoDBRoleConfig.Name,
		logger:     m.logger,
	}, nil
}

func (m *MongoDBTest) Flags(fs *flag.FlagSet) {}
