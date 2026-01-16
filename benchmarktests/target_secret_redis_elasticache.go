// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

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
	RedisElastiCacheSecretTestType        = "redis_elasticache_secret"
	RedisElastiCacheSecretTestMethod      = "GET"
	RedisElastiCacheAccessKeyIdEnvVar     = VaultBenchmarkEnvVarPrefix + "REDIS_ELASTICACHE_ACCESS_KEY_ID"
	RedisElastiCacheSecretAccessKeyEnvVar = VaultBenchmarkEnvVarPrefix + "REDIS_ELASTICACHE_SECRET_ACCESS_KEY"
	RedisElastiCacheRegionEnvVar          = VaultBenchmarkEnvVarPrefix + "REDIS_ELASTICACHE_REGION"
	RedisElastiCacheUsernameEnvVar        = VaultBenchmarkEnvVarPrefix + "REDIS_ELASTICACHE_USERNAME"
)

func init() {
	TestList[RedisElastiCacheSecretTestType] = func() BenchmarkBuilder { return &RedisElastiCacheSecret{} }
}

type RedisElastiCacheSecret struct {
	pathPrefix string
	roleName   string
	header     http.Header
	config     *RedisElastiCacheSecretTestConfig
	logger     hclog.Logger
}

type RedisElastiCacheSecretTestConfig struct {
	DBConfig   *RedisElastiCacheDBConfig   `hcl:"db_connection,block"`
	RoleConfig *RedisElastiCacheRoleConfig `hcl:"static_role,block"`
}

// Redis ElastiCache DB Config
type RedisElastiCacheDBConfig struct {
	// Common database config
	Name             string   `hcl:"name,optional"`
	PluginName       string   `hcl:"plugin_name,optional"`
	PluginVersion    string   `hcl:"plugin_version,optional"`
	VerifyConnection *bool    `hcl:"verify_connection,optional"`
	AllowedRoles     []string `hcl:"allowed_roles,optional"`

	// Redis ElastiCache specific config
	URL             string `hcl:"url"`
	AccessKeyId     string `hcl:"access_key_id,optional"`
	SecretAccessKey string `hcl:"secret_access_key,optional"`
	Region          string `hcl:"region,optional"`

	// Deprecated but supported for backward compatibility
	Username string `hcl:"username,optional"`
	Password string `hcl:"password,optional"`
}

type RedisElastiCacheRoleConfig struct {
	Name           string `hcl:"name,optional"`
	DBName         string `hcl:"db_name,optional"`
	Username       string `hcl:"username"`
	RotationPeriod string `hcl:"rotation_period,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (r *RedisElastiCacheSecret) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *RedisElastiCacheSecretTestConfig `hcl:"config,block"`
	}{
		Config: &RedisElastiCacheSecretTestConfig{
			DBConfig: &RedisElastiCacheDBConfig{
				Name:            "benchmark-redis-elasticache",
				PluginName:      "redis-elasticache-database-plugin",
				AllowedRoles:    []string{"benchmark-role"},
				AccessKeyId:     os.Getenv(RedisElastiCacheAccessKeyIdEnvVar),
				SecretAccessKey: os.Getenv(RedisElastiCacheSecretAccessKeyEnvVar),
				Region:          os.Getenv(RedisElastiCacheRegionEnvVar),
			},
			RoleConfig: &RedisElastiCacheRoleConfig{
				Name:           "benchmark-role",
				DBName:         "benchmark-redis-elasticache",
				Username:       os.Getenv(RedisElastiCacheUsernameEnvVar),
				RotationPeriod: "5m",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	r.config = testConfig.Config

	// Validate required parameters
	if r.config.DBConfig.URL == "" {
		return fmt.Errorf("no redis elasticache url provided but required")
	}

	if r.config.RoleConfig.Username == "" {
		return fmt.Errorf("no redis elasticache username provided but required")
	}

	if r.config.RoleConfig.RotationPeriod == "" {
		return fmt.Errorf("no redis elasticache rotation_period provided but required")
	}

	return nil
}

// Target returns a vegeta.Target for the Redis ElastiCache secret test
func (r *RedisElastiCacheSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RedisElastiCacheSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/static-creds/" + r.roleName,
		Header: r.header,
	}
}

// Cleanup removes the mount created during the test setup
func (r *RedisElastiCacheSecret) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

// GetTargetInfo returns the target info for Redis ElastiCache secret test
func (r *RedisElastiCacheSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RedisElastiCacheSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

// Setup configures the database secrets engine with Redis ElastiCache plugin
func (r *RedisElastiCacheSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RedisElastiCacheSecretTestType)
	setupLogger := r.logger.Named(RedisElastiCacheSecretTestType)

	if topLevelConfig.RandomMounts {
		secretUuid, err := uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
		secretPath = fmt.Sprintf("%s-%s", mountName, secretUuid)
	}

	// Enable database secrets engine
	setupLogger.Trace(mountLogMessage("secrets", "database", secretPath))
	mountInfo := &api.MountInput{
		Type: "database",
	}
	err = client.Sys().Mount(secretPath, mountInfo)
	if err != nil {
		return nil, fmt.Errorf("error mounting database secrets engine: %v", err)
	}

	// Decode DB Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("database config"))
	dbData, err := structToMap(r.config.DBConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing db config from struct: %v", err)
	}

	// Set up database connection
	setupLogger.Trace(writingLogMessage("redis elasticache db config"), "name", r.config.DBConfig.Name)
	dbPath := filepath.Join(secretPath, "config", r.config.DBConfig.Name)
	_, err = client.Logical().Write(dbPath, dbData)
	if err != nil {
		return nil, fmt.Errorf("error writing redis elasticache db config: %v", err)
	}

	// Decode Role Config struct into mapstructure to pass with request
	setupLogger.Trace(parsingConfigLogMessage("static role"))
	roleData, err := structToMap(r.config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Static Role
	setupLogger.Trace(writingLogMessage("redis elasticache static role"), "name", r.config.RoleConfig.Name)
	rolePath := filepath.Join(secretPath, "static-roles", r.config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error writing redis elasticache static role %q: %v", r.config.RoleConfig.Name, err)
	}

	return &RedisElastiCacheSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RoleConfig.Name,
		logger:     r.logger,
	}, nil
}

func (r *RedisElastiCacheSecret) Flags(fs *flag.FlagSet) {}
