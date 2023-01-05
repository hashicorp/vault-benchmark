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

type postgresqltest struct {
	pathPrefix string
	header     http.Header
	roleName   string
}

type PostgreSQLDBConfig struct {
	pluginName             string   `json:"-"`
	VerifyConnection       bool     `json:"verify_connection"`
	AllowedRoles           []string `json:"-"`
	RootRotationStatements []string `json:"root_rotation_statements"`
	PasswordPolicy         string   `json:"password_policy"`
	ConnectionURL          string   `json:"connection_url"`
	MaxOpenConnections     int      `json:"max_open_connections"`
	MaxIdleConnections     int      `json:"max_idle_connections"`
	MaxConnectionLifetime  string   `json:"max_connection_lifetime"`
	Username               string   `json:"username"`
	Password               string   `json:"password"`
	UsernameTemplate       string   `json:"username_template"`
	DisableEscaping        bool     `json:"disable_escaping"`
}

type PostgreSQLRoleConfig struct {
	Name                 string `json:"-"`
	DBName               string `json:"-"`
	DefaultTTL           string `json:"default_ttl"`
	MaxTTL               string `json:"max_ttl"`
	CreationStatements   string `json:"creation_statements"`
	RevocationStatements string `json:"revocation_statements"`
	RollbackStatements   string `json:"rollback_statements"`
	RenewStatements      string `json:"renew_statements"`
	RotationStatements   string `json:"rotation_statements"`
}

func (r *PostgreSQLRoleConfig) FromJSON(path string) error {
	// Set defaults
	r.Name = "benchmark-role"
	r.DBName = "postgresql-benchmark-database"
	r.DefaultTTL = "1h"
	r.MaxTTL = "24h"
	r.CreationStatements = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(r); err != nil {
		return err
	}
	return nil
}

func (c *PostgreSQLDBConfig) FromJSON(path string) error {
	// Set postgresqlDB Plugin
	c.pluginName = "postgresql-database-plugin"
	c.AllowedRoles = []string{
		"benchmark-role",
	}

	if path == "" {
		return fmt.Errorf("no PostgreSQL config passed but is required")
	}

	// Then load JSON config
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
	case c.ConnectionURL == "":
		return fmt.Errorf("no connection URL passed but is required")
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}

func (c *postgresqltest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *postgresqltest) cleanup(client *api.Client) error {
	client.SetClientTimeout(time.Second * 600)

	// Revoke all leases
	_, err := client.Logical().Write(strings.Replace(c.pathPrefix, "/v1/", "/sys/leases/revoke-prefix/", 1), map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("error cleaning up leases: %v", err)
	}

	_, err = client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupPostgreSQL(client *api.Client, randomMounts bool, config *PostgreSQLDBConfig, roleConfig *PostgreSQLRoleConfig) (*postgresqltest, error) {
	postgresqlPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		postgresqlPath = "postgresql"
	}

	err = client.Sys().Mount(postgresqlPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(postgresqlPath+"/config/postgresql-benchmark-database", map[string]interface{}{
		"plugin_name":              config.pluginName,
		"username":                 config.Username,
		"password":                 config.Password,
		"allowed_roles":            config.AllowedRoles,
		"username_template":        config.UsernameTemplate,
		"verify_connection":        config.VerifyConnection,
		"root_rotation_statements": config.RootRotationStatements,
		"password_policy":          config.PasswordPolicy,
		"connection_url":           config.ConnectionURL,
		"max_open_connections":     config.MaxOpenConnections,
		"max_idle_connections":     config.MaxIdleConnections,
		"max_connection_lifetime":  config.MaxConnectionLifetime,
		"disable_escaping":         config.DisableEscaping,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(postgresqlPath+"/roles/"+roleConfig.Name, map[string]interface{}{
		"db_name":               roleConfig.DBName,
		"creation_statements":   roleConfig.CreationStatements,
		"default_ttl":           roleConfig.DefaultTTL,
		"max_ttl":               roleConfig.MaxTTL,
		"revocation_statements": roleConfig.RevocationStatements,
		"rollback_statements":   roleConfig.RollbackStatements,
		"renew_statements":      roleConfig.RenewStatements,
		"rotation_statements":   roleConfig.RotationStatements,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &postgresqltest{
		pathPrefix: "/v1/" + postgresqlPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Name,
	}, nil
}
