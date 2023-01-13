package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type mongotest struct {
	pathPrefix string
	header     http.Header
	roleName   string
}

type MongoDBConfig struct {
	PluginName        string   `json:"-"`
	AllowedRoles      []string `json:"-"`
	ConnectionURL     string   `json:"connection_url"`
	WriteConcern      string   `json:"write_concern"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	TLSCertificateKey string   `json:"tls_certificate_key"`
	TLSCA             string   `json:"tls_ca"`
	UsernameTemplate  string   `json:"username_template"`
}

type MongoRoleConfig struct {
	Name                 string `json:"name"`
	DBName               string `json:"db_name"`
	DefaultTTL           string `json:"default_ttl"`
	MaxTTL               string `json:"max_ttl"`
	CreationStatements   string `json:"creation_statements"`
	RevocationStatements string `json:"revocation_statements"`
	RollbackStatements   string `json:"rollback_statements"`
}

func (r *MongoRoleConfig) FromJSON(path string) error {
	// Set defaults
	r.Name = "benchmark-role"
	r.DBName = "mongo-benchmark-database"
	r.DefaultTTL = "1h"
	r.MaxTTL = "24h"
	r.CreationStatements = "{ \"db\": \"admin\", \"roles\": [{ \"role\": \"readWrite\" }, {\"role\": \"read\", \"db\": \"foo\"}] }"

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

func (c *MongoDBConfig) FromJSON(path string) error {
	// Set MongoDB Plugin
	c.PluginName = "mongodb-database-plugin"
	c.AllowedRoles = []string{
		"benchmark-role",
	}

	if path == "" {
		return fmt.Errorf("no MongoDB config passed but is required")
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
		return fmt.Errorf("no connection url passed but is required")
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}

func (c *mongotest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *mongotest) cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupMongo(client *api.Client, randomMounts bool, config *MongoDBConfig, roleConfig *MongoRoleConfig) (*mongotest, error) {
	mongoPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		mongoPath = "mongo"
	}

	err = client.Sys().Mount(mongoPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(mongoPath+"/config/mongo-benchmark-database", map[string]interface{}{
		"plugin_name":         config.PluginName,
		"allowed_roles":       config.AllowedRoles,
		"connection_url":      config.ConnectionURL,
		"write_concern":       config.WriteConcern,
		"username":            config.Username,
		"password":            config.Password,
		"tls_certificate_key": config.TLSCertificateKey,
		"tls_ca":              config.TLSCA,
		"username_template":   config.UsernameTemplate,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(mongoPath+"/roles/"+roleConfig.Name, map[string]interface{}{
		"db_name":             roleConfig.DBName,
		"creation_statements": roleConfig.CreationStatements,
		"default_ttl":         roleConfig.DefaultTTL,
		"max_ttl":             roleConfig.MaxTTL,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &mongotest{
		pathPrefix: "/v1/" + mongoPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Name,
	}, nil
}
