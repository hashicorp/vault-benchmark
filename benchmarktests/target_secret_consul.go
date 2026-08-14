// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	ConsulSecretTestType   = "consul_secret"
	ConsulSecretTestMethod = "GET"
	ConsulTokenEnvVar      = VaultBenchmarkEnvVarPrefix + "CONSUL_TOKEN"
)

func init() {
	TestList[ConsulSecretTestType] = func() BenchmarkBuilder { return &ConsulSecret{} }
}

type ConsulSecret struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *ConsulSecretConfig
	logger     hclog.Logger
}

type ConsulSecretConfig struct {
	Version          string            `hcl:"version,optional"`
	ConsulConfig     *ConsulConfig     `hcl:"consul,block"`
	ConsulRoleConfig *ConsulRoleConfig `hcl:"role,block"`
}

type ConsulConfig struct {
	Address    string `hcl:"address"`
	Scheme     string `hcl:"scheme,optional"`
	Token      string `hcl:"token,optional"`
	CaCert     string `hcl:"ca_cert,optional"`
	ClientCert string `hcl:"client_cert,optional"`
	ClientKey  string `hcl:"client_key,optional"`
}

type ConsulRoleConfig struct {
	Partition         string   `hcl:"partition,optional"`
	NodeIdentities    []string `hcl:"node_identities,optional"`
	ConsulNamespace   string   `hcl:"consul_namespace,optional"`
	ServiceIdentities []string `hcl:"service_identities,optional"`
	ConsulRoles       []string `hcl:"consul_roles,optional"`
	Name              string   `hcl:"name,optional"`
	TokenType         string   `hcl:"token_type,optional"`
	Policy            string   `hcl:"policy,optional"`
	Policies          []string `hcl:"policies,optional"`
	ConsulPolicies    []string `hcl:"consul_policies,optional"`
	Local             bool     `hcl:"local,optional"`
	TTL               string   `hcl:"ttl,optional"`
	MaxTTL            string   `hcl:"max_ttl,optional"`
	Lease             string   `hcl:"lease,optional"`
}

func (c *ConsulSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *ConsulSecretConfig `hcl:"config,block"`
	}{
		Config: &ConsulSecretConfig{
			Version: "1.14.0",
			ConsulConfig: &ConsulConfig{
				Token: os.Getenv(ConsulTokenEnvVar),
			},
			ConsulRoleConfig: &ConsulRoleConfig{
				Name: "benchmark-role",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config

	if c.config.ConsulConfig.Token == "" {
		return fmt.Errorf("consul token must be set")
	}
	return nil
}

func (c *ConsulSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	c.logger = targetLogger.Named(ConsulSecretTestType)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	c.logger.Trace(mountLogMessage("secrets", "consul", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "consul",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting consul: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	setupLogger.Trace(parsingConfigLogMessage("consul"))
	if err := writeStruct(client, secretPath+"/config/access", c.config.ConsulConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace("parsing consul version from config")
	v, err := version.NewVersion(c.config.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing consul version: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	consulRoleConfigData, err := structToMap(c.config.ConsulRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	if v.LessThan(version.Must(version.NewVersion("1.8"))) {
		delete(consulRoleConfigData, "node_identities")
		delete(consulRoleConfigData, "consul_namespace")
		setupLogger.Warn("node_identities and consul_namespace are not supported in Consul < 1.8.  These fields will be ignored.")
	}

	if v.LessThan(version.Must(version.NewVersion("1.5"))) {
		delete(consulRoleConfigData, "service_identities")
		delete(consulRoleConfigData, "consul_roles")
		setupLogger.Warn("service_identities and consul_roles are not supported in Consul < 1.5.  These fields will be ignored.")
	}

	setupLogger.Trace(writingLogMessage("consul role"), "name", c.config.ConsulRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+c.config.ConsulRoleConfig.Name, consulRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing consul role: %v", err)
	}

	return &ConsulSecret{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   c.config.ConsulRoleConfig.Name,
		logger:     c.logger,
	}, nil
}

func (c *ConsulSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: ConsulSecretTestMethod,
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *ConsulSecret) Cleanup(client *api.Client) error {
	return cleanupMount(c.logger, client, c.pathPrefix)
}

func (c *ConsulSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     ConsulSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *ConsulSecret) Flags(fs *flag.FlagSet) {}
