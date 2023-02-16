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

type rabbittest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
}

type RabbitMQConfig struct {
	ConnectionURI    string `json:"connection_uri"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	VerifyConnection bool   `json:"verify_connection"`
	PasswordPolicy   string `json:"password_policy"`
	UsernameTemplate string `json:"username_template"`
}

type RabbitMQRoleConfig struct {
	Name        string `json:"name"`
	Tags        string `json:"tags"`
	Vhosts      string `json:"vhosts"`
	VhostTopics string `json:"vhost_topics"`
}

func (r *RabbitMQRoleConfig) FromJSON(path string) error {
	// Set defaults
	r.Name = "benchmark-role"
	r.Vhosts = "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}"

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

func (c *RabbitMQConfig) FromJSON(path string) error {

	if path == "" {
		return fmt.Errorf("no RabbitMQ config passed but is required")
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
	case c.ConnectionURI == "":
		return fmt.Errorf("no connection url passed but is required")
	case c.Username == "":
		return fmt.Errorf("no username passed but is required")
	case c.Password == "":
		return fmt.Errorf("no password passed but is required")
	default:
		return nil
	}
}

func (c *rabbittest) read(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *rabbittest) cleanup(client *api.Client) error {
	client.SetClientTimeout(c.timeout)

	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}

	return nil
}

func setupRabbit(client *api.Client, randomMounts bool, config *RabbitMQConfig, roleConfig *RabbitMQRoleConfig, timeout time.Duration) (*rabbittest, error) {
	rabbitPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		rabbitPath = "rabbit"
	}

	err = client.Sys().Mount(rabbitPath, &api.MountInput{
		Type: "rabbitmq",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(rabbitPath+"/config/connection", map[string]interface{}{
		"connection_uri":    config.ConnectionURI,
		"username":          config.Username,
		"password":          config.Password,
		"verify_connection": config.VerifyConnection,
		"password_policy":   config.PasswordPolicy,
		"username_template": config.UsernameTemplate,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(rabbitPath+"/roles/"+roleConfig.Name, map[string]interface{}{
		"name":         roleConfig.Name,
		"tags":         roleConfig.Tags,
		"vhosts":       roleConfig.Vhosts,
		"vhost_topics": roleConfig.VhostTopics,
	})

	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &rabbittest{
		pathPrefix: "/v1/" + rabbitPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		roleName:   roleConfig.Name,
		timeout:    timeout,
	}, nil
}
