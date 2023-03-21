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

var flagStaticRedisUserConfigHCL string

// Constants for test
const (
	RedisStaticSecretTestType   = "redis_static_secret"
	RedisStaticSecretTestMethod = "GET"
)

func init() {
	TestList[RedisStaticSecretTestType] = func() BenchmarkBuilder { return &RedisStaticSecret{} }
}

type RedisStaticSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *RedisStaticTestConfig
}

type RedisStaticTestConfig struct {
	Config *RedisStaticSecretTestConfig `hcl:"config,block"`
}

type RedisStaticSecretTestConfig struct {
	DBConfig   *RedisDBConfig         `hcl:"db,block"`
	RoleConfig *RedisStaticRoleConfig `hcl:"role,block"`
}

// Redis DB Config
type RedisDBConfig struct {
	DBName       string   `hcl:"db_name,optional"`
	PluginName   string   `hcl:"plugin_name,optional"`
	AllowedRoles []string `hcl:"allowed_roles,optional"`
	Host         string   `hcl:"host"`
	Port         int      `hcl:"port"`
	Username     string   `hcl:"username,optional"`
	Password     string   `hcl:"password,optional"`
	TLS          bool     `hcl:"tls,optional"`
	InsecureTLS  bool     `hcl:"insecure_tls,optional"`
	CACert       string   `hcl:"ca_cert,optional"`
}

type RedisStaticRoleConfig struct {
	RoleName       string `hcl:"role_name,optional"`
	RotationPeriod string `hcl:"rotation_period,optional"`
	Username       string `hcl:"username"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (s *RedisStaticSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	s.config = &RedisStaticTestConfig{
		Config: &RedisStaticSecretTestConfig{
			DBConfig: &RedisDBConfig{
				DBName:       "benchmark-redis-db",
				PluginName:   "redis-database-plugin",
				AllowedRoles: []string{"my-*-role"},
				TLS:          false,
				InsecureTLS:  true,
			},
			RoleConfig: &RedisStaticRoleConfig{
				RoleName:       "my-static-role",
				RotationPeriod: "5m",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, s.config)

	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Handle passed in JSON config
	if flagStaticRedisUserConfigHCL != "" {
		err := s.config.Config.DBConfig.FromJSON(flagStaticRedisUserConfigHCL)
		if err != nil {
			return fmt.Errorf("error loading redis user config from JSON: %v", err)
		}
	}
	return nil
}

func (s *RedisStaticSecret) Target(client *api.Client) vegeta.Target {
	var url string

	url = fmt.Sprintf("%s%s/creds/%s", client.Address(), s.pathPrefix, s.roleName)

	return vegeta.Target{
		Method: RedisStaticSecretTestMethod,
		URL:    url,
		Header: s.header,
	}
}

func (s *RedisStaticSecret) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up redis mount: %v", err)
	}
	return nil
}

func (s *RedisStaticSecret) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     RedisStaticSecretTestMethod,
		pathPrefix: s.pathPrefix,
	}
	return tInfo
}

// TODO: remove redis_test_user_json flag when we support environment variables
func (s *RedisStaticSecret) Flags(fs *flag.FlagSet) {
	fs.StringVar(&flagStaticRedisUserConfigHCL, "redis_static_test_user_json", "", "When provided, the location of user credentials to test redis secrets engine.")
}

func (s *RedisStaticSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
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
		return nil, fmt.Errorf("error decoding redis static DB Role config from struct: %v", err)
	}

	// Set Up Role
	rolePath := filepath.Join(secretPath, "roles", roleName)
	roleData["db_name"] = config.DBConfig.DBName

	_, err = client.Logical().Write(rolePath, roleData)

	if err != nil {
		return nil, fmt.Errorf("error creating redis role %q: %v", roleName, err)
	}

	return &RedisStaticSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   roleName,
		config:     s.config,
	}, nil
}
