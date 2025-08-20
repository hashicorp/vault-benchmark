// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	CubbyholeSecretReadTestType    = "cubbyhole_read"
	CubbyholeSecretWriteTestType   = "cubbyhole_write"
	CubbyholeSecretReadTestMethod  = "GET"
	CubbyholeSecretWriteTestMethod = "POST"
	CubbyholePathPrefix            = "/v1/cubbyhole"
	DefaultSecretPath              = "my-path"
)

func init() {
	// "Register" these tests to the main test registry
	TestList[CubbyholeSecretReadTestType] = func() BenchmarkBuilder {
		return &CubbyholeTest{action: "read"}
	}
	TestList[CubbyholeSecretWriteTestType] = func() BenchmarkBuilder {
		return &CubbyholeTest{action: "write"}
	}
}

type CubbyholeTest struct {
	pathPrefix string
	secretPath string
	header     http.Header
	config     *CubbyholeSecretTestConfig
	action     string
	logger     hclog.Logger
	baseURL    string
}

type CubbyholeSecretTestConfig struct {
	Path string `hcl:"path"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
func (c *CubbyholeTest) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *CubbyholeSecretTestConfig `hcl:"config,block"`
	}{
		Config: &CubbyholeSecretTestConfig{
			Path: DefaultSecretPath,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config
	if c.config.Path == "" {
		c.config.Path = DefaultSecretPath // Set default if empty instead of error
	}
	return nil
}

func (c *CubbyholeTest) read() vegeta.Target {
	return vegeta.Target{
		Method: CubbyholeSecretReadTestMethod,
		URL:    c.baseURL,
		Header: c.header,
	}
}

func (c *CubbyholeTest) write() vegeta.Target {
	return vegeta.Target{
		Method: CubbyholeSecretWriteTestMethod,
		URL:    c.baseURL,
		Body:   []byte(`{"foo": "bar"}`),
		Header: c.header,
	}
}

func (c *CubbyholeTest) Target(client *api.Client) vegeta.Target {
	switch c.action {
	case "write":
		return c.write()
	default:
		return c.read()
	}
}

func (c *CubbyholeTest) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	// Cubbyhole secrets are automatically cleaned up when token is revoked
	// But we can explicitly delete the secret if needed
	_, err := client.Logical().Delete(fmt.Sprintf("cubbyhole/%s", c.config.Path))
	if err != nil {
		return fmt.Errorf("error cleaning up cubbyhole secret: %v", err)
	}
	return nil
}

func (c *CubbyholeTest) GetTargetInfo() TargetInfo {
	var method string
	switch c.action {
	case "write":
		method = CubbyholeSecretWriteTestMethod
	default:
		method = CubbyholeSecretReadTestMethod
	}
	return TargetInfo{
		method:     method,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CubbyholeTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	switch c.action {
	case "write":
		c.logger = targetLogger.Named(CubbyholeSecretWriteTestType)
	default:
		c.logger = targetLogger.Named(CubbyholeSecretReadTestType)
	}
	// Generate a unique secret key if randomization is requested
	secretPath := c.config.Path
	if topLevelConfig.RandomMounts {
		randomSuffix, err := uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
		secretPath = fmt.Sprintf("%s-%s", c.config.Path, randomSuffix)
	}
	setupLogger := c.logger.Named("cubbyhole")

	// Cubbyhole is built-in at /cubbyhole/, no mounting required
	setupLogger.Trace("Setting up cubbyhole secret")

	// Write secret data to cubbyhole
	setupLogger.Trace(writingLogMessage("cubbyhole secret"), "key", secretPath)
	secretDataPath := fmt.Sprintf("cubbyhole/%s", secretPath)

	secretData := map[string]interface{}{
		"foo": "bar",
	}
	_, err := client.Logical().Write(secretDataPath, secretData)
	if err != nil {
		return nil, fmt.Errorf("error writing cubbyhole secret: %v", err)
	}

	// Update the config with the potentially randomized secret key
	configCopy := *c.config
	configCopy.Path = secretPath
	baseURL := fmt.Sprintf("%s%s/%s", client.Address(), CubbyholePathPrefix, secretPath)

	return &CubbyholeTest{
		pathPrefix: CubbyholePathPrefix,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		secretPath: "cubbyhole",
		action:     c.action,
		config:     &configCopy,
		logger:     c.logger,
		baseURL:    baseURL,
	}, nil
}

func (c *CubbyholeTest) Flags(fs *flag.FlagSet) {}
