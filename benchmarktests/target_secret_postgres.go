package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	PostgreSQLSecretTestType   = "postgresql_secret"
	PostgreSQLSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[PostgreSQLSecretTestType] = func() BenchmarkBuilder { return &PostgreSQLSecret{} }
}

// Approle Auth Test Struct
type PostgreSQLSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *PostgreSQLTestConfig
}

// Main Config Struct
type PostgreSQLTestConfig struct {
	Config *PostgreSQLSecretTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type PostgreSQLSecretTestConfig struct {
	PostgreSQLDBConfig   *PostgreSQLDBConfig   `hcl:"postgresql_db_config,block"`
	PostgreSQLRoleConfig *PostgreSQLRoleConfig `hcl:"postgresql_role_config,block"`
}

// PostgreSQL DB Config
type PostgreSQLDBConfig struct {
	Name                   string   `hcl:"name,optional"`
	VerifyConnection       bool     `hcl:"verify_connection,optional"`
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
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *PostgreSQLSecret) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     PostgreSQLSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
	return tInfo
}

func (s *PostgreSQLSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := s.config.Config

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error enabling postgresql secrets engine: %v", err)
	}

	// Decode DB Config struct into mapstructure to pass with request
	dbData, err := structToMap(config.PostgreSQLDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding db config from struct: %v", err)
	}

	// add plugin name to mapstruct
	dbData["plugin_name"] = "postgresql-database-plugin"

	// Set up db
	dbPath := filepath.Join(secretPath, "config", config.PostgreSQLDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)

	if err != nil {
		return nil, fmt.Errorf("error creating postgresql db %q: %v", config.PostgreSQLRoleConfig.Name, err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	roleData, err := structToMap(config.PostgreSQLRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding postgres DB Role config from struct: %v", err)
	}

	// Set Up Role
	rolePath := filepath.Join(secretPath, "roles", config.PostgreSQLRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating postgresql role %q: %v", config.PostgreSQLRoleConfig.Name, err)
	}

	// Create Role
	_, err = client.Logical().Write(secretPath+"/roles/"+config.PostgreSQLRoleConfig.Name, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &PostgreSQLSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.PostgreSQLRoleConfig.Name,
	}, nil

}

func (l *PostgreSQLSecret) Flags(fs *flag.FlagSet) {}
