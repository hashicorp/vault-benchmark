package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type consultest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
}

type ConsulConfig struct {
	Address    string `json:"address"`
	Scheme     string `json:"scheme"`
	Token      string `json:"token"`
	CaCert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	Version    string `json:"version"`
}

type ConsulRoleConfig struct {
	Partition         string   `json:"partition"`
	NodeIdentities    []string `json:"node_identities"`
	ConsulNamespace   string   `json:"consul_namespace"`
	ServiceIdentities []string `json:"service_identities"`
	ConsulRoles       []string `json:"consul_roles"`
	Name              string   `json:"name"`
	TokenType         string   `json:"token_type"`
	Policy            string   `json:"policy"`
	Policies          []string `json:"policies"`
	ConsulPolicies    []string `json:"consul_policies"`
	Local             bool     `json:"local"`
	TTL               string   `json:"ttl"`
	MaxTTL            string   `json:"max_ttl"`
	Lease             string   `json:"lease"`
}

func (r *ConsulRoleConfig) FromJSON(path string) error {
	// Set defaults
	r.Name = "benchmark-role"
	r.TokenType = "client"
	r.Local = false

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

func (c *ConsulConfig) FromJSON(path string) error {

	// Set defaults
	c.Scheme = "http"
	c.Version = "1.14.0"

	if path == "" {
		return fmt.Errorf("no Consul config passed but is required")
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
	case c.Address == "":
		return fmt.Errorf("no address passed but is required")
	default:
		return nil
	}
}

func (c *consultest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *consultest) cleanup(client *api.Client) error {
	client.SetClientTimeout(c.timeout)

	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func setupConsul(client *api.Client, randomMounts bool, config *ConsulConfig, roleConfig *ConsulRoleConfig, timeout time.Duration) (*consultest, error) {
	consulPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		consulPath = "consul"
	}

	err = client.Sys().Mount(consulPath, &api.MountInput{
		Type: "consul",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting consul: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(consulPath+"/config/access", map[string]interface{}{
		"address":     config.Address,
		"scheme":      config.Scheme,
		"token":       config.Token,
		"ca_cert":     config.CaCert,
		"client_cert": config.ClientCert,
		"client_key":  config.ClientKey,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing consul config: %v", err)
	}

	// Get consul version
	v, err := version.NewVersion(config.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing consul version: %v", err)
	}

	configs := map[string]interface{}{
		"token_type":      roleConfig.TokenType,
		"policy":          roleConfig.Policy,
		"policies":        roleConfig.Policies,
		"consul_policies": roleConfig.ConsulPolicies,
		"local":           roleConfig.Local,
		"ttl":             roleConfig.TTL,
		"max_ttl":         roleConfig.MaxTTL,
	}
	switch {
	case v.GreaterThanOrEqual(version.Must(version.NewVersion("1.8"))):
		configs["node_identities"] = roleConfig.NodeIdentities
		configs["consul_namespace"] = roleConfig.ConsulNamespace
	case v.GreaterThanOrEqual(version.Must(version.NewVersion("1.5"))):
		configs["service_identities"] = roleConfig.ServiceIdentities
		configs["consul_roles"] = roleConfig.ConsulRoles
	}

	// Create Role
	_, err = client.Logical().Write(consulPath+"/roles/"+roleConfig.Name, configs)

	if err != nil {
		return nil, fmt.Errorf("error writing consul role: %v", err)
	}

	return &consultest{
		pathPrefix: "/v1/" + consulPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Name,
		timeout:    timeout,
	}, nil
}
