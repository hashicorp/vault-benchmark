package benchmarktests

import (
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

// Constants for test
const (
	RedisStaticSecretTestType       = "redis_static_secret"
	RedisStaticSecretTestMethod     = "GET"
	RedisStaticSecretUsernameEnvVar = VaultBenchmarkEnvVarPrefix + "STATIC_REDIS_USERNAME"
	RedisStaticSecretPasswordEnvVar = VaultBenchmarkEnvVarPrefix + "STATIC_REDIS_PASSWORD"
)

func init() {
	TestList[RedisStaticSecretTestType] = func() BenchmarkBuilder { return &RedisStaticSecret{} }
}

type RedisStaticSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *RedisStaticTestConfig
	logger     hclog.Logger
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
	// Common
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`
	CACert           string   `hcl:"ca_cert,optional"`
	PluginVersion    string   `hcl:"plugin_version,optional"`
	VerifyConnection *bool    `hcl:"verify_connection,optional"`

	// Redis specific
	Host        string `hcl:"host"`
	Port        int    `hcl:"port"`
	Username    string `hcl:"username,optional"`
	Password    string `hcl:"password,optional"`
	TLS         bool   `hcl:"tls,optional"`
	InsecureTLS bool   `hcl:"insecure_tls,optional"`
}

type RedisStaticRoleConfig struct {
	Name           string `hcl:"name,optional"`
	DBName         string `hcl:"db_name,optional"`
	RotationPeriod string `hcl:"rotation_period,optional"`
	Username       string `hcl:"username"`
	InsecureTLS    bool   `hcl:"insecure_tls,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (r *RedisStaticSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	r.config = &RedisStaticTestConfig{
		Config: &RedisStaticSecretTestConfig{
			DBConfig: &RedisDBConfig{
				Name:         "benchmark-redis-db",
				PluginName:   "redis-database-plugin",
				AllowedRoles: []string{"my-*-role"},
				TLS:          false,
				InsecureTLS:  true,
				Username:     os.Getenv(RedisStaticSecretUsernameEnvVar),
				Password:     os.Getenv(RedisStaticSecretPasswordEnvVar),
			},
			RoleConfig: &RedisStaticRoleConfig{
				DBName:         "benchmark-redis-db",
				Name:           "my-static-role",
				RotationPeriod: "5m",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, r.config)

	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	if r.config.Config.DBConfig.Username == "" {
		return fmt.Errorf("no redis username provided but required")
	}

	if r.config.Config.DBConfig.Password == "" {
		return fmt.Errorf("no redis password provided but required")
	}

	return nil
}

func (r *RedisStaticSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedisStaticSecretTestMethod,
		URL:    fmt.Sprintf("%s%s/creds/%s", client.Address(), r.pathPrefix, r.roleName),
		Header: r.header,
	}
}

func (r *RedisStaticSecret) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *RedisStaticSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedisStaticSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RedisStaticSecret) Flags(fs *flag.FlagSet) {}

func (r *RedisStaticSecret) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := r.config.Config
	r.logger = targetLogger.Named(RedisStaticSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Database Secret Mount
	r.logger.Trace(mountLogMessage("secrets", "database", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "database",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling database secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("db"))
	dbData, err := structToMap(config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up db
	setupLogger.Trace(writingLogMessage("redis db config"), "name", config.DBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", config.DBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing redis db config: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Set Up Role
	setupLogger.Trace(writingLogMessage("redis role"), "name", config.RoleConfig.Name)
	rolePath := filepath.Join(secretPath, "roles", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing redis role %q: %v", config.RoleConfig.Name, err)
	}

	return &RedisStaticSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.RoleConfig.Name,
		config:     r.config,
		logger:     r.logger,
	}, nil
}
