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

var flagRedisUserConfighcl string

// Constants for test
const (
	RedisSecretTestType   = "redis_secret"
	RedisSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[RedisSecretTestType] = func() BenchmarkBuilder { return &RedisSecret{} }
}

type RedisSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *RedisTestConfig
}

// Main Config Struct
type RedisTestConfig struct {
	Config *RedisSecretTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type RedisSecretTestConfig struct {
	RedisDBConfig          *RedisDBConfig          `hcl:"db_config,block"`
	DynamicRedisRoleConfig *RedisDynamicRoleConfig `hcl:"dynamic_role_config,block"`
	StaticRedisRoleConfig  *RedisStaticRoleConfig  `hcl:"static_role_config,block"`
}

// Redi DB Config
type RedisDBConfig struct {
	DBName       string   `hcl:"db_name,optional"`
	AllowedRoles []string `hcl:"allowed_roles,optional"`
	Host         string   `hcl:"host"`
	Port         int      `hcl:"port"` // check default
	Username     string   `hcl:"username"`
	Password     string   `hcl:"password"`
	TLS          bool     `hcl:"tls,optional"`          // check default
	InsecureTLS  bool     `hcl:"insecure_tls,optional"` // check default
	CACert       string   `hcl:"ca_cert,optional"`
}

type RedisDynamicRoleConfig struct {
	RoleName           string `hcl:"role_name,optional"`
	DefaultTTL         string `hcl:"default_ttl,optional"`
	MaxTTL             string `hcl:"max_ttl,optional"`
	CreationStatements string `hcl:"creation_statements"`
}

type RedisStaticRoleConfig struct {
	RoleName       string `hcl:"role_name,optional"`
	RotationPeriod string `hcl:"rotation_period,optional"`
	Username       string `hcl:"username"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (s *RedisSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	s.config = &RedisTestConfig{
		Config: &RedisSecretTestConfig{
			RedisDBConfig: &RedisDBConfig{
				DBName:       "benchmark-redis-db",
				AllowedRoles: []string{"*"},
				TLS:          false,
				InsecureTLS:  true,
			},
			DynamicRedisRoleConfig: &RedisDynamicRoleConfig{
				RoleName: "benchmark-redis-role",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, s.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Handle passed in JSON config
	if flagRedisUserConfighcl != "" {
		err := s.config.Config.RedisDBConfig.FromJSON(flagRedisUserConfighcl)
		if err != nil {
			return fmt.Errorf("error loading redis user config from JSON: %v", err)
		}
	}
	return nil
}

func (s *RedisSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedisSecretTestMethod,
		URL:    client.Address() + s.pathPrefix + "/creds/" + s.roleName,
		Header: s.header,
	}
}

func (s *RedisSecret) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up redis mount: %v", err)
	}
	return nil
}

func (s *RedisSecret) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     RedisSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
	return tInfo
}

func (s *RedisSecret) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagRedisUserConfighcl, "redis_test_user_json", "", "When provided, the location of user credentials to test redis secrets engine.")
}

func (s *RedisSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
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
	dbData, err := structToMap(config.RedisDBConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding db config from struct: %v", err)
	}

	// add plugin name to mapstruct
	dbData["plugin_name"] = "redis-database-plugin"

	// Set up db
	dbPath := filepath.Join(secretPath, "config", config.RedisDBConfig.DBName)
	_, err = client.Logical().Write(dbPath, dbData)

	if err != nil {
		return nil, fmt.Errorf("error creating redis db %q: %v", config.DynamicRedisRoleConfig.RoleName, err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	roleData, err := structToMap(config.DynamicRedisRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding redis DB Role config from struct: %v", err)
	}

	// Set Up Role
	rolePath := filepath.Join(secretPath, "roles", config.DynamicRedisRoleConfig.RoleName)
	roleData["db_name"] = dbData["db_name"]
	_, err = client.Logical().Write(rolePath, roleData)

	if err != nil {
		return nil, fmt.Errorf("error creating redis role %q: %v", config.DynamicRedisRoleConfig.RoleName, err)
	}

	// Create Role
	_, err = client.Logical().Write(secretPath+"/roles/"+config.DynamicRedisRoleConfig.RoleName, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &RedisSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.DynamicRedisRoleConfig.RoleName,
	}, nil

}

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
