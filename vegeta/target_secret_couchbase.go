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

type couchbasetest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
}

type CouchbaseConfig struct {
	pluginName       string   `json:"-"`
	Hosts            string   `json:"hosts"`
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	AllowedRoles     []string `json:"-"`
	TLS              bool     `json:"tls"`
	InsecureTLS      bool     `json:"insecure_tls"`
	UsernameTemplate string   `json:"username_template"`
	Base64PEM        string   `json:"base64pem"`
	BucketName       string   `json:"bucket_name"`
}

type CouchbaseRoleConfig struct {
	Name               string `json:"-"`
	DBName             string `json:"-"`
	DefaultTTL         string `json:"default_ttl"`
	MaxTTL             string `json:"max_ttl"`
	CreationStatements string `json:"creation_statements"`
}

func (r *CouchbaseRoleConfig) FromJSON(path string) error {
	// Set defaults
	r.Name = "benchmark-role"
	r.DBName = "couchbase-benchmark-database"
	r.DefaultTTL = "1h"
	r.MaxTTL = "24h"
	r.CreationStatements = "{\"Roles\": [{\"role\":\"ro_admin\"}]}"

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

func (c *CouchbaseConfig) FromJSON(path string) error {
	// Set defaults
	c.pluginName = "couchbase-database-plugin"
	c.AllowedRoles = []string{
		"benchmark-role",
	}
	c.TLS = false

	if path == "" {
		return fmt.Errorf("no Couchbase config passed but is required")
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
	case c.Hosts == "":
		return fmt.Errorf("no hosts passed but is required")
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}

func (c *couchbasetest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *couchbasetest) cleanup(client *api.Client) error {
	client.SetClientTimeout(c.timeout)

	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupCouchbase(client *api.Client, randomMounts bool, config *CouchbaseConfig, roleConfig *CouchbaseRoleConfig, timeout time.Duration) (*couchbasetest, error) {
	couchbasePath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		couchbasePath = "couchbase"
	}

	err = client.Sys().Mount(couchbasePath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(couchbasePath+"/config/couchbase-benchmark-database", map[string]interface{}{
		"plugin_name":       config.pluginName,
		"hosts":             config.Hosts,
		"username":          config.Username,
		"password":          config.Password,
		"allowed_roles":     config.AllowedRoles,
		"tls":               config.TLS,
		"insecure_tls":      config.InsecureTLS,
		"username_template": config.UsernameTemplate,
		"base64pem":         config.Base64PEM,
		"bucket_name":       config.BucketName,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(couchbasePath+"/roles/"+roleConfig.Name, map[string]interface{}{
		"db_name":             roleConfig.DBName,
		"creation_statements": roleConfig.CreationStatements,
		"default_ttl":         roleConfig.DefaultTTL,
		"max_ttl":             roleConfig.MaxTTL,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &couchbasetest{
		pathPrefix: "/v1/" + couchbasePath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Name,
		timeout:    timeout,
	}, nil
}
