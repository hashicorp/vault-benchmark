package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	CassandraSecretTestType   = "cassandra_secret"
	CassandraSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[CassandraSecretTestType] = func() BenchmarkBuilder { return &CassandraSecret{} }
}

// Cassandra Secret Test Struct
type CassandraSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *CassandraTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type CassandraTestConfig struct {
	Config *CassandraSecretTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type CassandraSecretTestConfig struct {
	CassandraDBConfig   *CassandraDBConfig   `hcl:"db,block"`
	CassandraRoleConfig *CassandraRoleConfig `hcl:"role,block"`
}

// Cassandra DB Config
type CassandraDBConfig struct {
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	Hosts            string   `hcl:"hosts"`
	Port             int      `hcl:"port,optional"`
	ProtocolVersion  int      `hcl:"protocol_version"`
	Username         string   `hcl:"username"`
	Password         string   `hcl:"password"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`
	TLS              *bool    `hcl:"tls,optional"`
	InsecureTLS      bool     `hcl:"insecure_tls,optional"`
	TLSServerName    string   `hcl:"tls_server_name,optional"`
	PEMBundle        string   `hcl:"pem_bundle,optional"`
	PEMhcl           string   `hcl:"pem_hcl,optional"`
	SkipVerification bool     `hcl:"skip_verification,optional"`
	ConnectTimeout   string   `hcl:"connect_timeout,optional"`
	LocalDatacenter  string   `hcl:"local_datacenter,optional"`
	SocketKeepAlive  string   `hcl:"socket_keep_alive,optional"`
	Consistency      string   `hcl:"consistency,optional"`
	UsernameTemplate string   `hcl:"username_template,optional"`
}

// Cassandra Role Config
type CassandraRoleConfig struct {
	Name                 string `hcl:"name,optional"`
	DBName               string `hcl:"db_name,optional"`
	DefaultTTL           string `hcl:"default_ttl,optional"`
	MaxTTL               string `hcl:"max_ttl,optional"`
	CreationStatements   string `hcl:"creation_statements"`
	RevocationStatements string `hcl:"revocation_statements,optional"`
	RollbackStatements   string `hcl:"rollback_statements,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (c *CassandraSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	c.config = &CassandraTestConfig{
		Config: &CassandraSecretTestConfig{
			CassandraDBConfig: &CassandraDBConfig{
				Name:         "benchmark-cassandra",
				PluginName:   "cassandra-database-plugin",
				AllowedRoles: []string{"benchmark-role"},
				Port:         9042,
			},
			CassandraRoleConfig: &CassandraRoleConfig{
				Name:   "benchmark-role",
				DBName: "benchmark-cassandra",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, c.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	return nil
}

func (c *CassandraSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CassandraSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *CassandraSecret) Cleanup(client *api.Client) error {
	c.logger.Trace("unmounting", "path", hclog.Fmt("%v", c.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (c *CassandraSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CassandraSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CassandraSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := c.config.Config
	c.logger = targetLogger.Named(CassandraSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}
	c.logger = c.logger.Named(secretPath)

	// Create Database Secret Mount
	c.logger.Trace("mounting database secrets engine at", "path", hclog.Fmt("%v", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling cassandra secrets engine: %v", err)
	}

	// Decode DB Config struct into mapstructure to pass with request
	c.logger.Trace("parsing db config data")
	dbData, err := structToMap(config.CassandraDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding db config from struct: %v", err)
	}

	// Set up db
	c.logger.Trace("writing db config", "name", hclog.Fmt("%v", config.CassandraDBConfig.Name))
	dbPath := filepath.Join(secretPath, "config", config.CassandraDBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error creating cassandra db %q: %v", config.CassandraDBConfig.Name, err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	c.logger.Trace("parsing role config data")
	roleData, err := structToMap(config.CassandraRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding cassandra DB Role config from struct: %v", err)
	}

	// Set Up Role
	c.logger.Trace("writing role", "name", hclog.Fmt("%v", config.CassandraRoleConfig.Name))
	rolePath := filepath.Join(secretPath, "roles", config.CassandraRoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating cassandra role %q: %v", config.CassandraRoleConfig.Name, err)
	}

	return &CassandraSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.CassandraRoleConfig.Name,
	}, nil

}

func (c *CassandraSecret) Flags(fs *flag.FlagSet) {}
