package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type redistest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
}

type RedisConfig struct {
	DBName       string   `json:"db_name"`
	AllowedRoles []string `json:"allowed_roles"`
	Host         string   `json:"host"`
	Port         *int     `json:"port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	TLS          *bool    `json:"tls"`
	InsecureTLS  *bool    `json:"insecure_tls"`
	CACert       string   `json:"ca_cert"`
}

type RedisDynamicRoleConfig struct {
	RoleName           string `json:"role_name"`
	DefaultTTL         string `json:"default_ttl"`
	MaxTTL             string `json:"max_ttl"`
	CreationStatements string `json:"creation_statements"`
}

type RedisStaticRoleConfig struct {
	RoleName       string `json:"role_name"`
	RotationPeriod string `json:"rotation_period"`
	Username       string `json:"username"`
}

func (c *RedisConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no redis config passed but is required")
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

	// Check for required fields in RedisConfig
	switch {
	case c.Host == "":
		return fmt.Errorf("no host passed but is required")
	case c.Port == nil:
		return fmt.Errorf("no port passed but is required")
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	}

	// Set defaults
	defaultAllowedRoles := []string{"*"}
	defaultDBName := "redis"
	defaultTLS := false
	defaultInsecureTLS := true

	if len(c.AllowedRoles) == 0 {
		c.AllowedRoles = defaultAllowedRoles
	}

	if c.DBName == "" {
		c.DBName = defaultDBName
	}

	if c.TLS == nil {
		c.TLS = &defaultTLS
	}

	if c.InsecureTLS == nil {
		c.InsecureTLS = &defaultInsecureTLS
	}

	return nil
}

func (r *RedisDynamicRoleConfig) FromJSON(path string) error {
	// defaults
	defaultRoleName := "benchmark-role"
	defaultCreationStatement := "[\"+@admin\"]"
	defaultTTL := "1h"
	defaultMaxTTL := "24h"

	if path == "" {
		r.RoleName = defaultRoleName
		r.CreationStatements = defaultCreationStatement
		r.DefaultTTL = defaultTTL
		r.MaxTTL = defaultMaxTTL
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(r); err != nil {
		return err
	}

	if r.RoleName == "" {
		r.RoleName = defaultRoleName
	}

	if r.CreationStatements == "" {
		r.CreationStatements = defaultCreationStatement
	}

	if r.DefaultTTL == "" {
		r.DefaultTTL = defaultTTL
	}

	if r.MaxTTL == "" {
		r.MaxTTL = defaultMaxTTL
	}

	return nil
}

func (r *RedisStaticRoleConfig) FromJSON(path string) error {
	// defaults
	defaultRoleName := "benchmark-role"
	defaultUsername := "vault-admin"
	defaultRotationPeriod := "5m"

	if path == "" {
		r.RoleName = defaultRoleName
		r.Username = defaultUsername
		r.RotationPeriod = defaultRotationPeriod
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(r); err != nil {
		return err
	}

	if r.RoleName == "" {
		r.RoleName = defaultRoleName
	}

	if r.Username == "" {
		r.Username = defaultUsername
	}

	if r.RotationPeriod == "" {
		r.RotationPeriod = defaultRotationPeriod
	}

	return nil
}

func (c *redistest) readDynamic(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *redistest) readStatic(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/static-creds/" + c.roleName,
		Header: c.header,
	}
}

func (r *redistest) cleanup(client *api.Client) error {
	client.SetClientTimeout(r.timeout)

	// Revoke all leases
	_, err := client.Logical().Write(strings.Replace(r.pathPrefix, "/v1/", "/sys/leases/revoke-prefix/", 1), map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("error cleaning up leases: %v", err)
	}

	_, err = client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupDynamicRoleRedis(client *api.Client, randomMounts bool, config *RedisConfig, roleConfig *RedisDynamicRoleConfig) (*redistest, error) {
	redisPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}

	if !randomMounts {
		redisPath = "redis"
	}

	err = client.Sys().Mount(redisPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	configPath := fmt.Sprintf("%s/config/%s", redisPath, config.DBName)
	_, err = client.Logical().Write(configPath, map[string]interface{}{
		"plugin_name":   "redis-database-plugin",
		"allowed_roles": config.AllowedRoles,
		"host":          config.Host,
		"port":          *config.Port,
		"username":      config.Username,
		"password":      config.Password,
		"ca_cert":       config.CACert,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing redis db config: %v", err)
	}

	// Create Role
	rolePath := fmt.Sprintf("%v/roles/%v", redisPath, roleConfig.RoleName)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"db_name":             config.DBName,
		"creation_statements": roleConfig.CreationStatements,
		"default_ttl":         roleConfig.DefaultTTL,
		"max_ttl":             roleConfig.MaxTTL,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing redis db role: %v", err)
	}

	return &redistest{
		pathPrefix: "/v1/" + redisPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.RoleName,
	}, nil
}

func setupStaticRoleRedis(client *api.Client, randomMounts bool, config *RedisConfig, roleConfig *RedisStaticRoleConfig) (*redistest, error) {
	redisPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}

	if !randomMounts {
		redisPath = "redis"
	}

	err = client.Sys().Mount(redisPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	configPath := fmt.Sprintf("%s/config/%s", redisPath, config.DBName)
	_, err = client.Logical().Write(configPath, map[string]interface{}{
		"plugin_name":   "redis-database-plugin",
		"allowed_roles": config.AllowedRoles,
		"host":          config.Host,
		"port":          *config.Port,
		"username":      config.Username,
		"password":      config.Password,
		"ca_cert":       config.CACert,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing redis db config: %v", err)
	}

	// Create Role
	rolePath := fmt.Sprintf("%v/static-roles/%v", redisPath, roleConfig.RoleName)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"db_name":         config.DBName,
		"username":        roleConfig.Username,
		"rotation_period": roleConfig.RotationPeriod,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing redis db role: %v", err)
	}

	return &redistest{
		pathPrefix: "/v1/" + redisPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.RoleName,
	}, nil
}
