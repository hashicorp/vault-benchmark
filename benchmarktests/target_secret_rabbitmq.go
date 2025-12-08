// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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
	RabbitMQSecretTestType   = "rabbitmq_secret"
	RabbitMQSecretTestMethod = "GET"
	RabbitMQUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "RABBITMQ_USERNAME"
	RabbitMQPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "RABBITMQ_PASSWORD"
)

func init() {
	// "Register" this test to the main test registry
	TestList[RabbitMQSecretTestType] = func() BenchmarkBuilder { return &RabbitMQTest{} }
}

type RabbitMQTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *RabbitMQSecretTestConfig
	logger     hclog.Logger
}

// Main Config Struct
type RabbitMQSecretTestConfig struct {
	RabbitMQConnectionConfig *RabbitMQConnectionConfig `hcl:"connection,block"`
	RabbitMQRoleConfig       *RabbitMQRoleConfig       `hcl:"role,block"`
}

type RabbitMQConnectionConfig struct {
	ConnectionURI    string `hcl:"connection_uri"`
	Username         string `hcl:"username,optional"`
	Password         string `hcl:"password,optional"`
	VerifyConnection *bool  `hcl:"verify_connection,optional"`
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
	testConfig := &struct {
		Config *RabbitMQSecretTestConfig `hcl:"config,block"`
	}{
		Config: &RabbitMQSecretTestConfig{
			RabbitMQConnectionConfig: &RabbitMQConnectionConfig{
				Username: os.Getenv(RabbitMQUsernameEnvVar),
				Password: os.Getenv(RabbitMQPasswordEnvVar),
			},
			RabbitMQRoleConfig: &RabbitMQRoleConfig{
				Name:   "benchmark-role",
				Vhosts: "{\"/\":{\"write\": \".*\", \"read\": \".*\"}}",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	r.config = testConfig.Config

	if r.config.RabbitMQConnectionConfig.Username == "" {
		return fmt.Errorf("no rabbitmq username provided but required")
	}

	if r.config.RabbitMQConnectionConfig.Password == "" {
		return fmt.Errorf("no rabbitmq password provided but required")
	}

	return nil
}

func (r *RabbitMQTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RabbitMQSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *RabbitMQTest) Cleanup(client *api.Client) error {
	r.logger.Trace(cleanupLogMessage(r.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(r.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (r *RabbitMQTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RabbitMQSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (r *RabbitMQTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RabbitMQSecretTestType)

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	r.logger.Trace(mountLogMessage("secrets", "rabbitmq", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "rabbitmq",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting rabbitmq secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	// Decode RabbitMQ Connection Config
	setupLogger.Trace(parsingConfigLogMessage("rabbitmq connection"))
	connectionConfigData, err := structToMap(r.config.RabbitMQConnectionConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing rabbitmq connection config from struct: %v", err)
	}

	// Write connection config
	setupLogger.Trace(writingLogMessage("rabbitmq connection config"))
	_, err = client.Logical().Write(secretPath+"/config/connection", connectionConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing rabbitmq connection config: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleConfigData, err := structToMap(r.config.RabbitMQRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("rabbitmq role"), "name", r.config.RabbitMQRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+r.config.RabbitMQRoleConfig.Name, roleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing rabbitmq role: %v", err)
	}

	return &RabbitMQTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RabbitMQRoleConfig.Name,
		logger:     r.logger,
	}, nil
}

func (m *RabbitMQTest) Flags(fs *flag.FlagSet) {}
