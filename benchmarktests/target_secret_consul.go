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
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	ConsulSecretTestType   = "consul_secret"
	ConsulSecretTestMethod = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[ConsulSecretTestType] = func() BenchmarkBuilder { return &ConsulTest{} }
}

type ConsulTest struct {
	pathPrefix string
	header     http.Header
	roleName   string
	config     *ConsulTestConfig
	logger     hclog.Logger
}

type ConsulTestConfig struct {
	Config *ConsulSecretTestConfig `hcl:"config,block"`
}

type ConsulSecretTestConfig struct {
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
	Version    string `hcl:"version"`
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

func (c *ConsulTest) ParseConfig(body hcl.Body) error {
	c.config = &ConsulTestConfig{
		Config: &ConsulSecretTestConfig{
			ConsulConfig: &ConsulConfig{
				Scheme:  "http",
				Version: "1.14.0",
				Token:   os.Getenv("CONSUL_TOKEN"),
			},
			ConsulRoleConfig: &ConsulRoleConfig{
				Name:      "benchmark-role",
				TokenType: "client",
				Local:     false,
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, c.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	// Ensure that the token has been set by either the environment variable or the default value
	if c.config.Config.ConsulConfig.Token == "" {
		return fmt.Errorf("consul token must be set")
	}
	return nil
}

func (c *ConsulTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "GET",
		URL:    client.Address() + c.pathPrefix + "/creds/" + c.roleName,
		Header: c.header,
	}
}

func (c *ConsulTest) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (c *ConsulTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     ConsulSecretTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *ConsulTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := c.config.Config
	c.logger = targetLogger.Named(ConsulSecretTestType)

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	c.logger.Trace(mountLogMessage("secrets", "consul", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "consul",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting consul: %v", err)
	}

	setupLogger := c.logger.Named(secretPath)

	// Decode Consul Config
	setupLogger.Trace(parsingConfigLogMessage("consul"))
	consulConfigData, err := structToMap(config.ConsulConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing consul config from struct: %v", err)
	}

	// Write Consul config
	setupLogger.Trace(writingLogMessage("consul config"))
	_, err = client.Logical().Write(secretPath+"/config/access", consulConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing consul config: %v", err)
	}

	// Get consul version
	setupLogger.Trace("parsing consul version from config")
	v, err := version.NewVersion(config.ConsulConfig.Version)
	if err != nil {
		return nil, fmt.Errorf("error parsing consul version: %v", err)
	}

	// Decode Role Config
	setupLogger.Trace(parsingConfigLogMessage("role"))
	consulRoleConfigData, err := structToMap(config.ConsulRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	switch {
	case v.GreaterThanOrEqual(version.Must(version.NewVersion("1.8"))):
		consulRoleConfigData["node_identities"] = config.ConsulRoleConfig.NodeIdentities
		consulRoleConfigData["consul_namespace"] = config.ConsulRoleConfig.ConsulNamespace
	case v.GreaterThanOrEqual(version.Must(version.NewVersion("1.5"))):
		consulRoleConfigData["service_identities"] = config.ConsulRoleConfig.ServiceIdentities
		consulRoleConfigData["consul_roles"] = config.ConsulRoleConfig.ConsulRoles
	}

	// Create Role
	setupLogger.Trace(writingLogMessage("consul role"), "name", config.ConsulRoleConfig.Name)
	_, err = client.Logical().Write(secretPath+"/roles/"+config.ConsulRoleConfig.Name, consulRoleConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing consul role: %v", err)
	}

	return &ConsulTest{
		pathPrefix: "/v1/" + secretPath,
		header:     generateHeader(client),
		roleName:   config.ConsulRoleConfig.Name,
		logger:     c.logger,
	}, nil
}

func (c *ConsulTest) Flags(fs *flag.FlagSet) {}
