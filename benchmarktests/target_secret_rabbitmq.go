// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	RabbitMQSecretTestType   = "rabbitmq_secret"
	RabbitMQSecretTestMethod = "GET"
	RabbitMQUsernameEnvVar   = VaultBenchmarkEnvVarPrefix + "RABBITMQ_USERNAME"
	RabbitMQPasswordEnvVar   = VaultBenchmarkEnvVarPrefix + "RABBITMQ_PASSWORD"
)

func init() {
	TestList[RabbitMQSecretTestType] = func() BenchmarkBuilder { return &RabbitMQSecret{} }
}

type RabbitMQSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *RabbitMQSecretConfig
	logger     hclog.Logger
}

type RabbitMQSecretConfig struct {
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

func (r *RabbitMQSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *RabbitMQSecretConfig `hcl:"config,block"`
	}{
		Config: &RabbitMQSecretConfig{
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

func (r *RabbitMQSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	r.logger = targetLogger.Named(RabbitMQSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	r.logger.Trace(mountLogMessage("secrets", "rabbitmq", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "rabbitmq",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting rabbitmq secrets engine: %v", err)
	}

	setupLogger := r.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("rabbitmq connection"))
	if err := writeStruct(client, secretPath+"/config/connection", r.config.RabbitMQConnectionConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, secretPath+"/roles/"+r.config.RabbitMQRoleConfig.Name, r.config.RabbitMQRoleConfig); err != nil {
		return nil, err
	}

	return &RabbitMQSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   r.config.RabbitMQRoleConfig.Name,
		logger:     r.logger,
	}, nil
}

func (r *RabbitMQSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: RabbitMQSecretTestMethod,
		URL:    client.Address() + r.pathPrefix + "/creds/" + r.roleName,
		Header: r.header,
	}
}

func (r *RabbitMQSecret) Cleanup(client *api.Client) error {
	return cleanupMount(r.logger, client, r.pathPrefix)
}

func (r *RabbitMQSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     RabbitMQSecretTestMethod,
		pathPrefix: r.pathPrefix,
	}
}

func (m *RabbitMQSecret) Flags(fs *flag.FlagSet) {}
