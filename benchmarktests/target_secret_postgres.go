package benchmarktests

import (
	"encoding/json"
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

var flagPostgreSQLUserConfigJSON string

// Constants for test
const (
	PostgreSQLSecretTestType   = "postgresql_secret"
	PostgreSQLSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[PostgreSQLSecretTestType] = func() BenchmarkBuilder { return &PostgreSQLSecret{} }
}

// Postgres Secret Test Struct
type PostgreSQLSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *PostgreSQLTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type PostgreSQLTestConfig struct {
	Config *PostgreSQLSecretTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type PostgreSQLSecretTestConfig struct {
	PostgreSQLDBConfig   *PostgreSQLDBConfig   `hcl:"db_config,block"`
	PostgreSQLRoleConfig *PostgreSQLRoleConfig `hcl:"role_config,block"`
}

// PostgreSQL DB Config
type PostgreSQLDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection,optional"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	ConnectionURL          string   `hcl:"connection_url"`
	MaxOpenConnections     int      `hcl:"max_open_connections,optional"`
	MaxIdleConnections     int      `hcl:"max_idle_connections,optional"`
	MaxConnectionLifetime  string   `hcl:"max_connection_lifetime,optional"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
	DisableEscaping        bool     `hcl:"disable_escaping,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
}

// PostgreSQL Role Config
type PostgreSQLRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
	RollbackStatements   string `hcl:"rollback_statements,optional"`
	RenewStatements      string `hcl:"renew_statements,optional"`
	RotationStatements   string `hcl:"rotation_statements,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (s *PostgreSQLSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	s.config = &PostgreSQLTestConfig{
		Config: &PostgreSQLSecretTestConfig{
			PostgreSQLDBConfig: &PostgreSQLDBConfig{
				Name:         "benchmark-postgres",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "postgresql-database-plugin",
			},
			PostgreSQLRoleConfig: &PostgreSQLRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-postgres",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, s.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Handle passed in JSON config
	if flagPostgreSQLUserConfigJSON != "" {
		err := s.config.Config.PostgreSQLDBConfig.FromJSON(flagPostgreSQLUserConfigJSON)
		if err != nil {
			return fmt.Errorf("error loading test postgres user config from JSON: %v", err)
		}
	}
	return nil
}

func (s *PostgreSQLSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: PostgreSQLSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *PostgreSQLSecret) Cleanup(client *api.Client) error {
	s.logger.Trace("unmounting", "path", hclog.Fmt("%v", s.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *PostgreSQLSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     PostgreSQLSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *PostgreSQLSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := s.config.Config
	s.logger = targetLogger.Named(PostgreSQLSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	s.logger.Trace("mounting db secrets engine at path", "path", hclog.Fmt("%v", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling db secrets engine: %v", err)
	}

	setupLogger := s.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace("parsing postgres db config data")
	dbData, err := structToMap(config.PostgreSQLDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace("writing postgres db config data")
	dbPath := filepath.Join(secretPath, "config", config.PostgreSQLDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error creating postgresql db %q: %v", config.PostgreSQLRoleConfig.Name, err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace("parsing role config data")
	roleData, err := structToMap(config.PostgreSQLRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding postgres DB Role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace("writing role", "name", hclog.Fmt("%v", config.PostgreSQLRoleConfig.Name))
	rolePath := filepath.Join(secretPath, "roles", config.PostgreSQLRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating postgresql role %q: %v", config.PostgreSQLRoleConfig.Name, err)
	}

	return &PostgreSQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.PostgreSQLRoleConfig.Name,
	}, nil

}

func (l *PostgreSQLSecret) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagPostgreSQLUserConfigJSON, "postgres_test_user_json", "", "When provided, the location of user credentials to test postgres secrets engine.")
}

func (c *PostgreSQLDBConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no postgres user config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(c); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}
