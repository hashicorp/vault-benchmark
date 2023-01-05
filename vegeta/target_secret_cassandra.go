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

type cassandratest struct {
	pathPrefix string
	header     http.Header
	roleName   string
}

type CassandraDBConfig struct {
	pluginName       string   `json:"-"`
	Hosts            string   `json:"hosts"`
	Port             int      `json:"port"`
	ProtocolVersion  int      `json:"protocol_version"`
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	AllowedRoles     []string `json:"-"`
	TLS              bool     `json:"tls"`
	InsecureTLS      bool     `json:"insecure_tls"`
	TLSServerName    string   `json:"tls_server_name"`
	PEMBundle        string   `json:"pem_bundle"`
	PEMJSON          string   `json:"pem_json"`
	SkipVerification bool     `json:"skip_verification"`
	ConnectTimeout   string   `json:"connect_timeout"`
	LocalDatacenter  string   `json:"local_datacenter"`
	SocketKeepAlive  string   `json:"socket_keep_alive"`
	Consistency      string   `json:"consistency"`
	UsernameTemplate string   `json:"username_template"`
}

type CassandraRoleConfig struct {
	Name                 string `json:"-"`
	DBName               string `json:"-"`
	DefaultTTL           string `json:"default_ttl"`
	MaxTTL               string `json:"max_ttl"`
	CreationStatements   string `json:"creation_statements"`
	RevocationStatements string `json:"revocation_statements"`
	RollbackStatements   string `json:"rollback_statements"`
}

func (r *CassandraRoleConfig) FromJSON(path string) error {
	// Set defaults
	r.Name = "benchmark-role"
	r.DBName = "cassandra-benchmark-database"
	r.DefaultTTL = "1h"
	r.MaxTTL = "24h"
	r.CreationStatements = "CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER; GRANT SELECT ON ALL KEYSPACES TO {{username}};"

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

func (c *CassandraDBConfig) FromJSON(path string) error {
	// Set CassandraDB Plugin
	c.pluginName = "cassandra-database-plugin"
	c.AllowedRoles = []string{
		"benchmark-role",
	}

	if path == "" {
		return fmt.Errorf("no CassandraDB config passed but is required")
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

func (c *cassandratest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *cassandratest) cleanup(client *api.Client) error {
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

func setupCassandra(client *api.Client, randomMounts bool, config *CassandraDBConfig, roleConfig *CassandraRoleConfig) (*cassandratest, error) {
	cassandraPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		cassandraPath = "cassandra"
	}

	err = client.Sys().Mount(cassandraPath, &api.MountInput{
		Type: "database",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(cassandraPath+"/config/cassandra-benchmark-database", map[string]interface{}{
		"plugin_name":       config.pluginName,
		"hosts":             config.Hosts,
		"protocol_version":  config.ProtocolVersion,
		"username":          config.Username,
		"password":          config.Password,
		"allowed_roles":     config.AllowedRoles,
		"port":              config.Port,
		"tls":               config.TLS,
		"insecure_tls":      config.InsecureTLS,
		"tls_server_name":   config.TLSServerName,
		"pem_bundle":        config.PEMBundle,
		"pem_json":          config.PEMJSON,
		"skip_verification": config.SkipVerification,
		"connect_timeout":   config.ConnectTimeout,
		"local_datacenter":  config.LocalDatacenter,
		"socket_keep_alive": config.SocketKeepAlive,
		"consistency":       config.Consistency,
		"username_template": config.UsernameTemplate,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(cassandraPath+"/roles/"+roleConfig.Name, map[string]interface{}{
		"db_name":             roleConfig.DBName,
		"creation_statements": roleConfig.CreationStatements,
		"default_ttl":         roleConfig.DefaultTTL,
		"max_ttl":             roleConfig.MaxTTL,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &cassandratest{
		pathPrefix: "/v1/" + cassandraPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Name,
	}, nil
}
