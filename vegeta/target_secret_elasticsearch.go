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

type elasticsearchtest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
}

type ElasticSearchDBConfig struct {
	DBName       string `json:"db_name"`
	AllowedRoles string `json:"allowed_roles"`
	URL          string `json:"url"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Insecure     *bool  `json:"insecure"`
	CACert       string `json:"ca_cert"`
	ClientCert   string `json:"client_cert"`
	ClientKey    string `json:"client_key"`
}

type ElasticSearchRoleConfig struct {
	RoleName           string `json:"role_name"`
	DefaultTTL         string `json:"default_ttl"`
	MaxTTL             string `json:"max_ttl"`
	CreationStatements string `json:"creation_statements"`
}

func (c *ElasticSearchDBConfig) FromJSON(path string) error {
	if path == "" {
		return fmt.Errorf("no elastic search config passed but is required")
	}

	// Load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(c); err != nil {
		return err
	}

	// Check for required fields in ElasticSearchDBConfig
	switch {
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	case c.URL == "":
		return fmt.Errorf("no password passed but is required")
	}

	// Set defaults
	defaultDBName := "es-benchmark"
	defaultAllowedRoles := "internally-defined-role,externally-defined-role"
	defaultInsecure := true

	if c.DBName == "" {
		c.DBName = defaultDBName
	}

	if c.AllowedRoles == "" {
		c.AllowedRoles = defaultAllowedRoles
	}

	if c.Insecure == nil {
		c.Insecure = &defaultInsecure
	}

	return nil
}

func (r *ElasticSearchRoleConfig) FromJSON(path string) error {
	// defaults
	defaultRoleName := "internally-defined-role"
	defaultCreationStatement := "{\"elasticsearch_role_definition\": {\"indices\": [{\"names\":[\"*\"], \"privileges\":[\"read\"]}]}}"
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

	defer file.Close()

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

func (e *elasticsearchtest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + e.pathPrefix + "/creds/" + e.roleName,
		Header: e.header,
	}
}

func (r *elasticsearchtest) cleanup(client *api.Client) error {
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

func setupElasticSearch(client *api.Client, randomMounts bool, config *ElasticSearchDBConfig, roleConfig *ElasticSearchRoleConfig) (*elasticsearchtest, error) {
	elasticsearchPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}

	if !randomMounts {
		elasticsearchPath = "elasticsearch"
	}

	err = client.Sys().Mount(elasticsearchPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	configPath := fmt.Sprintf("%s/config/%s", elasticsearchPath, config.DBName)

	_, err = client.Logical().Write(configPath, map[string]interface{}{
		"plugin_name":   "elasticsearch-database-plugin",
		"allowed_roles": config.AllowedRoles,
		"url":           config.URL,
		"username":      config.Username,
		"password":      config.Password,
		"insecure":      config.Insecure,
		"ca_cert":       config.CACert,
		"client_cert":   config.ClientCert,
		"client_key":    config.ClientKey,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing Elasticsearch db config: %v", err)
	}

	// Create Role
	rolePath := fmt.Sprintf("%v/roles/%v", elasticsearchPath, roleConfig.RoleName)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"db_name":             config.DBName,
		"creation_statements": roleConfig.CreationStatements,
		"default_ttl":         roleConfig.DefaultTTL,
		"max_ttl":             roleConfig.MaxTTL,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing Elasticsearch db role: %v", err)
	}

	return &elasticsearchtest{
		pathPrefix: "/v1/" + elasticsearchPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.RoleName,
	}, nil
}
