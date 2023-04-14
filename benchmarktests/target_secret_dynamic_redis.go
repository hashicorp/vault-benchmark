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

var flagDynamicRedisUserConfigHCL string

// Constants for test
const (
	RedisDynamicSecretTestType   = "redis_dynamic_secret"
	RedisDynamicSecretTestMethod = "GET"
)

func init() {
	TestList[RedisDynamicSecretTestType] = func() BenchmarkBuilder { return &RedisDynamicSecret{} }
}

type RedisDynamicSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *RedisDynamicTestConfig
	logger     hclog.Logger
}

type RedisDynamicTestConfig struct {
	Config *RedisDynamicSecretTestConfig `hcl:"config,block"`
}

type RedisDynamicSecretTestConfig struct {
	DBConfig   *RedisDBConfig          `hcl:"db,block"`
	RoleConfig *RedisDynamicRoleConfig `hcl:"role,block"`
}

type RedisDynamicRoleConfig struct {
	Name               string `hcl:"name,optional"`
	DBName             string `hcl:"db_name,optional"`
	DefaultTTL         string `hcl:"default_ttl,optional"`
	MaxTTL             string `hcl:"max_ttl,optional"`
	CreationStatements string `hcl:"creation_statements"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (r *RedisDynamicSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	r.config = &RedisDynamicTestConfig{
		Config: &RedisDynamicSecretTestConfig{
			DBConfig: &RedisDBConfig{
				Name:         "benchmark-redis-db",
				PluginName:   "redis-database-plugin",
				AllowedRoles: []string{"my-*-role"},
				TLS:          false,
				InsecureTLS:  true,
			},
			RoleConfig: &RedisDynamicRoleConfig{
				Name:       "my-dynamic-role",
				DBName:     "benchmark-redis-db",
				DefaultTTL: "5m",
				MaxTTL:     "5m",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, r.config)

	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Handle passed in JSON config
	if flagDynamicRedisUserConfigHCL != "" {
		err := r.config.Config.DBConfig.FromJSON(flagDynamicRedisUserConfigHCL)
		if err != nil {
			return fmt.Errorf("error loading redis user config from JSON: %v", err)
		}
	}
	return nil
}

func (r *RedisDynamicSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedisDynamicSecretTestMethod,
		URL:    fmt.Sprintf("%s%s/creds/%s", client.Address(), r.pathPrefix, r.roleName),
		Header: r.header,
	}
}

func (r *RedisDynamicSecret) Cleanup(client *api.Client) error {
	r.logger.Trace("unmounting", "path", hclog.Fmt("%v", r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up redis mount: %v", err)
	}
	return nil
}

func (r *RedisDynamicSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedisDynamicSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

// TODO: remove redis_test_user_json flag when we support environment variables
func (r *RedisDynamicSecret) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagDynamicRedisUserConfigHCL, "redis_dynamic_test_user_json", "", "When provided, the location of user credentials to test redis secrets engine.")
}

func (r *RedisDynamicSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := r.config.Config
	r.logger = targetLogger.Named(RedisDynamicSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}
	r.logger = r.logger.Named(secretPath)

	// Create Database Secret Mount
	r.logger.Trace("mounting database secrets engine at", "path", hclog.Fmt("%v", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling redis secrets engine: %v", err)
	}

	// Decode DB Config struct into mapstructure to pass with request
	r.logger.Trace("parsing db config data")
	dbData, err := structToMap(config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding redis db config from struct: %v", err)
	}

	// Set up db
	r.logger.Trace("writing db config", "name", hclog.Fmt("%v", config.DBConfig.Name))
	dbPath := filepath.Join(secretPath, "config", config.DBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error creating redis db %q: %v", config.DBConfig.Name, err)
	}

	r.logger.Trace("parsing role config data")
	roleData, err := structToMap(config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding redis dynamic DB Role config from struct: %v", err)
	}

	// Set Up Role
	r.logger.Trace("writing role", "name", hclog.Fmt("%v", config.RoleConfig.Name))
	rolePath := filepath.Join(secretPath, "roles", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating redis role %q: %v", config.RoleConfig.Name, err)
	}

	return &RedisDynamicSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.RoleConfig.Name,
		config:     r.config,
		logger:     r.logger,
	}, nil
}

// TODO: remove when we support environment variables
func (d *RedisDBConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no redis user config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(d); err != nil {
		return err
	}

	// Check for required fields
	switch {
	case d.Username == "":
		return fmt.Errorf("no username passed but is required")
	case d.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}
