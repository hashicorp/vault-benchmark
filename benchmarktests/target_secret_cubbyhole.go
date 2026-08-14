// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
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
	TestList[CubbyholeSecretReadTestType] = func() BenchmarkBuilder {
		return &CubbyholeSecret{action: "read"}
	}
	TestList[CubbyholeSecretWriteTestType] = func() BenchmarkBuilder {
		return &CubbyholeSecret{action: "write"}
	}
}

type CubbyholeSecret struct {
	pathPrefix string
	header     http.Header
	body       []byte
	method     string
	targetURL  string
	action     string
	config     *CubbyholeSecretConfig
	logger     hclog.Logger
	secretPath string
}

type CubbyholeSecretConfig struct {
	Path string `hcl:"path"`
}

func (c *CubbyholeSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *CubbyholeSecretConfig `hcl:"config,block"`
	}{
		Config: &CubbyholeSecretConfig{
			Path: DefaultSecretPath,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config
	if c.config.Path == "" {
		c.config.Path = DefaultSecretPath
	}
	return nil
}

func (c *CubbyholeSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	switch c.action {
	case "write":
		c.logger = targetLogger.Named(CubbyholeSecretWriteTestType)
	default:
		c.logger = targetLogger.Named(CubbyholeSecretReadTestType)
	}

	secretPath := c.config.Path
	if topLevelConfig.RandomMounts {
		randomSuffix, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("error generating random mount name: %w", err)
		}
		secretPath = c.config.Path + "-" + randomSuffix
	}

	setupLogger := c.logger.Named("cubbyhole")
	setupLogger.Trace(writingLogMessage("cubbyhole secret"), "key", secretPath)
	_, err := client.Logical().Write("cubbyhole/"+secretPath, map[string]any{"foo": "bar"})
	if err != nil {
		return nil, fmt.Errorf("error writing cubbyhole secret: %v", err)
	}

	method := CubbyholeSecretReadTestMethod
	var body []byte
	if c.action == "write" {
		method = CubbyholeSecretWriteTestMethod
		body = []byte(`{"foo": "bar"}`)
	}

	return &CubbyholeSecret{
		pathPrefix: CubbyholePathPrefix,
		header: http.Header{
			"X-Vault-Token":     []string{client.Token()},
			"X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")},
		},
		body:       body,
		method:     method,
		targetURL:  client.Address() + CubbyholePathPrefix + "/" + secretPath,
		logger:     c.logger,
		secretPath: secretPath,
	}, nil
}

func (c *CubbyholeSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: c.method,
		URL:    c.targetURL,
		Body:   c.body,
		Header: c.header,
	}
}

func (c *CubbyholeSecret) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	_, err := client.Logical().Delete("cubbyhole/" + c.secretPath)
	if err != nil {
		return fmt.Errorf("error cleaning up cubbyhole secret: %v", err)
	}
	return nil
}

func (c *CubbyholeSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     c.method,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CubbyholeSecret) Flags(fs *flag.FlagSet) {}
