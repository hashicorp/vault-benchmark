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

var flagMSSQLUserConfigJSON string

// Constants for test
const (
	MSSQLSecretTestType   = "mssql_secret"
	MSSQLSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[MSSQLSecretTestType] = func() BenchmarkBuilder { return &MSSQLSecret{} }
}

// Postgres Secret Test Struct
type MSSQLSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *MSSQLTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type MSSQLTestConfig struct {
	Config *MSSQLSecretTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type MSSQLSecretTestConfig struct {
	MSSQLDBConfig   *MSSQLDBConfig   `hcl:"db,block"`
	MSSQLRoleConfig *MSSQLRoleConfig `hcl:"role,block"`
}

// MSSQL DB Config
type MSSQLDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	PluginName             string   `hcl:"plugin_name,optional"`
	PluginVersion          string   `hcl:"plugin_version,optional"`
	VerifyConnection       *bool    `hcl:"verify_connection,optional"`
	AllowedRoles           []string `hcl:"allowed_roles,optional"`
	RootRotationStatements []string `hcl:"root_rotation_statements,optional"`
	PasswordPolicy         string   `hcl:"password_policy,optional"`
	ConnectionURL          string   `hcl:"connection_url"`
	Username               string   `hcl:"username,optional"`
	Password               string   `hcl:"password,optional"`
	DisableEscaping        bool     `hcl:"disable_escaping,optional"`
	MaxOpenConnections     int      `hcl:"max_open_connections,optional"`
	MaxIdleConnections     int      `hcl:"max_idle_connections,optional"`
	MaxConnectionLifetime  string   `hcl:"max_connection_lifetime,optional"`
	UsernameTemplate       string   `hcl:"username_template,optional"`
	ContainedDB            bool     `hcl:"contained_db,optional"`
}

// MSSQL Role Config
type MSSQLRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (m *MSSQLSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	m.config = &MSSQLTestConfig{
		Config: &MSSQLSecretTestConfig{
			MSSQLDBConfig: &MSSQLDBConfig{
				Name:         "benchmark-mssql",
				AllowedRoles: []string{"benchmark-role"},
				PluginName:   "mssql-database-plugin",
			},
			MSSQLRoleConfig: &MSSQLRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-mssql",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, m.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Handle passed in JSON config
	if flagMSSQLUserConfigJSON != "" {
		err := m.config.Config.MSSQLDBConfig.FromJSON(flagMSSQLUserConfigJSON)
		if err != nil {
			return fmt.Errorf("error loading test mssql user config from JSON: %v", err)
		}
	}
	return nil
}

func (m *MSSQLSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: MSSQLSecretTestMethod,
		URL:    client.Address() + m.pathPrefix + "/creds/" + m.roleName,
		Header: m.header,
	}
}

func (m *MSSQLSecret) Cleanup(client *api.Client) error {
	m.logger.Trace(cleanupLogMessage(m.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(m.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (m *MSSQLSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     MSSQLSecretTestMethod,
		pathPrefix: m.pathPrefix,
	}
}

func (m *MSSQLSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := m.config.Config
	m.logger = targetLogger.Named(MSSQLSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	m.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting db secrets engine: %v", err)
	}

	setupLogger := m.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(config.MSSQLDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("mssql db config"), "name", config.MSSQLDBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", config.MSSQLDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing mssql db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(config.MSSQLRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("mssql role"), "name", config.MSSQLRoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", config.MSSQLRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing mssql role %q: %v", config.MSSQLRoleConfig.Name, err)
	}

	return &MSSQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.MSSQLRoleConfig.Name,
	}, nil

}

func (l *MSSQLSecret) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagMSSQLUserConfigJSON, "mssql_test_user_json", "", "When provided, the location of user credentials to test mssql secrets engine.")
}

func (c *MSSQLDBConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no mssql user config passed but is required")
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
