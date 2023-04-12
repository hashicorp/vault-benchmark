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
}

type RedisDynamicTestConfig struct {
	Config *RedisDynamicSecretTestConfig `hcl:"config,block"`
}

type RedisDynamicSecretTestConfig struct {
	DBConfig   *RedisDBConfig          `hcl:"db,block"`
	RoleConfig *RedisDynamicRoleConfig `hcl:"role,block"`
}

type RedisDynamicRoleConfig struct {
	RoleName           string `hcl:"role_name,optional"`
	DefaultTTL         string `hcl:"default_ttl,optional"`
	MaxTTL             string `hcl:"max_ttl,optional"`
	CreationStatements string `hcl:"creation_statements"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (s *RedisDynamicSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	s.config = &RedisDynamicTestConfig{
		Config: &RedisDynamicSecretTestConfig{
			DBConfig: &RedisDBConfig{
				DBName:       "benchmark-redis-db",
				PluginName:   "redis-database-plugin",
				AllowedRoles: []string{"my-*-role"},
				TLS:          false,
				InsecureTLS:  true,
			},
			RoleConfig: &RedisDynamicRoleConfig{
				RoleName:   "my-dynamic-role",
				DefaultTTL: "5m",
				MaxTTL:     "5m",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, s.config)

	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Handle passed in JSON config
	if flagDynamicRedisUserConfigHCL != "" {
		err := s.config.Config.DBConfig.FromJSON(flagDynamicRedisUserConfigHCL)
		if err != nil {
			return fmt.Errorf("error loading redis user config from JSON: %v", err)
		}
	}
	return nil
}

func (s *RedisDynamicSecret) Target(client *api.Client) vegeta.Target {
	var url string

	url = fmt.Sprintf("%s%s/creds/%s", client.Address(), s.pathPrefix, s.roleName)

	return vegeta.Target{
		Method: RedisDynamicSecretTestMethod,
		URL:    url,
		Header: s.header,
	}
}

func (s *RedisDynamicSecret) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up redis mount: %v", err)
	}
	return nil
}

func (s *RedisDynamicSecret) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     RedisDynamicSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
	return tInfo
}

// TODO: remove redis_test_user_json flag when we support environment variables
func (s *RedisDynamicSecret) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagDynamicRedisUserConfigHCL, "redis_dynamic_test_user_json", "", "When provided, the location of user credentials to test redis secrets engine.")
}

func (s *RedisDynamicSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
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
		return nil, fmt.Errorf("error enabling redis secrets engine: %v", err)
	}

	// Decode DB Config struct into mapstructure to pass with request
	dbData, err := structToMap(config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding redis db config from struct: %v", err)
	}

	// Set up db
	dbPath := filepath.Join(secretPath, "config", config.DBConfig.DBName)
	_, err = client.Logical().Write(dbPath, dbData)

	if err != nil {
		return nil, fmt.Errorf("error creating redis db %q: %v", config.DBConfig.DBName, err)
	}

	roleName := config.RoleConfig.RoleName
	roleData, err := structToMap(config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding redis dynamic DB Role config from struct: %v", err)
	}

	// Set Up Role
	rolePath := filepath.Join(secretPath, "roles", roleName)
	roleData["db_name"] = config.DBConfig.DBName

	_, err = client.Logical().Write(rolePath, roleData)

	if err != nil {
		return nil, fmt.Errorf("error creating redis role %q: %v", roleName, err)
	}

	return &RedisDynamicSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   roleName,
		config:     s.config,
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
