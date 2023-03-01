package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	RabbitMQSecretTestType   = "rabbitmq_secret"
	RabbitMQSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[RabbitMQSecretTestType] = func() BenchmarkBuilder { return &RabbitMQTest{} }
}

type RabbitMQTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	timeout    time.Duration
	config     *RabbitMQTestConfig
}

// Main Config Struct
type RabbitMQTestConfig struct {
	Config *RabbitMQSecretTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type RabbitMQSecretTestConfig struct {
	RabbitMQConfig     *RabbitMQConfig     `hcl:"rabbitmq_config,block"`
	RabbitMQRoleConfig *RabbitMQRoleConfig `hcl:"role_config,block"`
}

type RabbitMQConfig struct {
	ConnectionURI    string `hcl:"connection_uri"`
	Username         string `hcl:"username"`
	Password         string `hcl:"password"`
	VerifyConnection bool   `hcl:"verify_connection,optional"`
	PasswordPolicy   string `hcl:"password_policy,optional"`
	UsernameTemplate string `hcl:"username_template,optional"`
}

type RabbitMQRoleConfig struct {
	Name        string `hcl:"name,optional"`
	Tags        string `hcl:"tags,optional"`
	Vhosts      string `hcl:"vhosts"`
	VhostTopics string `hcl:"vhost_topics,optional"`
}

func (r *RabbitMQTest) ParseConfig(body hcl.Body) error {
	r.config = &RabbitMQTestConfig{
		Config: &RabbitMQSecretTestConfig{
			RabbitMQConfig: &RabbitMQConfig{},
			RabbitMQRoleConfig: &RabbitMQRoleConfig{
				Name:   "benchmark-role",
				Vhosts: "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, r.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (r *RabbitMQTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *RabbitMQTest) Cleanup(client *api.Client) error {
	client.SetClientTimeout(r.timeout)

	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *RabbitMQTest) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     RabbitMQSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
	return tInfo
}

func (r *RabbitMQTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := r.config.Config

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "rabbitmq",
	})

	if err != nil {
		return nil, fmt.Errorf("error mounting db: %v", err)
	}

	// Decode DB Config
	dbConfigData, err := structToMap(config.RabbitMQConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding RabbitMQ config from struct: %v", err)
	}

	// Write DB config
	_, err = client.Logical().Write(secretPath+"/config/connection", dbConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing db config: %v", err)
	}

	// Decode Role Config
	roleConfigData, err := structToMap(config.RabbitMQRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding RabbitMQ Role config from struct: %v", err)
	}

	// Create Role
	_, err = client.Logical().Write(secretPath+"/roles/"+config.RabbitMQRoleConfig.Name, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing db role: %v", err)
	}

	return &RabbitMQTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.RabbitMQRoleConfig.Name,
		timeout:    r.timeout,
	}, nil
}

func (m *RabbitMQTest) Flags(fs *flag.FlagSet) {}
