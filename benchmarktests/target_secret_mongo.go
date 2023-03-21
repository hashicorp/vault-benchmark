package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

var flagMongoDBUserConfigJSON string

const (
	MongoDBSecretTestType   = "mongodb_secret"
	MongoDBSecretTestMethod = "GET"
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
}

type MongoDBTestConfig struct {
	Config *MongoDBSecretTestConfig `hcl:"config,block"`
}

type MongoDBSecretTestConfig struct {
	MongoDBConfig     *MongoDBConfig     `hcl:"db_config,block"`
	MongoDBRoleConfig *MongoDBRoleConfig `hcl:"role_config,block"`
}

type MongoDBConfig struct {
	Name              string   `hcl:"name"`
	PluginName        string   `hcl:"plugin_name,optional"`
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
	DBName               string `hcl:"db_name"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements,optional"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
	RollbackStatements   string `hcl:"rollback_statements,optional"`
}

func (m *MongoDBTest) ParseConfig(body hcl.Body) error {
	m.config = &MongoDBTestConfig{
		Config: &MongoDBSecretTestConfig{
			MongoDBConfig: &MongoDBConfig{
				PluginName:   "mongodb-database-plugin",
				AllowedRoles: []string{"benchmark-role"},
			},
			MongoDBRoleConfig: &MongoDBRoleConfig{
				Name:               "benchmark-role",
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

	// Handle passed in JSON config
	if flagMongoDBUserConfigJSON != "" {
		err := m.config.Config.MongoDBConfig.FromJSON(flagMongoDBUserConfigJSON)
		if err != nil {
			return fmt.Errorf("error loading test mongodb user config from JSON: %v", err)
		}
	}

	// Ensure that the username and password are set
	if m.config.Config.MongoDBConfig.Username == "" || m.config.Config.MongoDBConfig.Password == "" {
		return fmt.Errorf("username and password must be set")
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
	_, err := client.Logical().Delete(strings.Replace(m.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (m *MongoDBTest) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     MongoDBSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
	return tInfo
}

func (m *MongoDBTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := m.config.Config

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
	dbConfigData, err := structToMap(config.MongoDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding MongoDB config from struct: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(secretPath+"/config/"+config.MongoDBConfig.Name, dbConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Decode Role Config
	roleConfigData, err := structToMap(config.MongoDBRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding MongoDB Role config from struct: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(secretPath+"/roles/"+config.MongoDBRoleConfig.Name, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &MongoDBTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.MongoDBRoleConfig.Name,
	}, nil
}

func (m *MongoDBTest) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagMongoDBUserConfigJSON, "mongodb_test_user_json", "", "When provided, the location of user credentials to test mongodb secrets engine.")
}

func (m *MongoDBConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no mongodb user config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(m); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case m.Username == "":
		return fmt.Errorf("no username passed but is required")
	case m.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}