// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	PKIKeyGenerationTestType   = "pki_generate_key"
	PKIKeyGenerationTestMethod = "POST"
)

func init() {
	TestList[PKIKeyGenerationTestType] = func() BenchmarkBuilder { return &PKIGenerateKey{} }
}

type PKIGenerateKey struct {
	pathPrefix string
	body       []byte
	header     http.Header
	config     *PKIGenerateKeyConfig
	logger     hclog.Logger
	mountPath  string
}

// PKIGenerateKeyConfig is the top-level HCL config block for this benchmark.
type PKIGenerateKeyConfig struct {
	SetupDelay        string                    `hcl:"setup_delay,optional"`
	GenerateKeyConfig *PKIGenerateKeyBodyConfig `hcl:"generate_key,block"`
}

// PKIGenerateKeyBodyConfig maps to POST /v1/<mount>/keys/generate/
type PKIGenerateKeyBodyConfig struct {
	Type           string `hcl:"type,optional"`
	KeyType        string `hcl:"key_type,optional"`
	KeyBits        int    `hcl:"key_bits,optional"`
	KeyName        string `hcl:"key_name,optional"`
	ManagedKeyName string `hcl:"managed_key_name,optional"`
	ManagedKeyID   string `hcl:"managed_key_id,optional"`
	ParameterSet   string `hcl:"parameter_set,optional"`
}

func (p *PKIGenerateKey) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *PKIGenerateKeyConfig `hcl:"config,block"`
	}{
		Config: &PKIGenerateKeyConfig{
			SetupDelay: "1s",
			GenerateKeyConfig: &PKIGenerateKeyBodyConfig{
				Type:    "internal",
				KeyType: "rsa",
				KeyBits: 2048,
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	p.config = testConfig.Config
	return nil
}

func (p *PKIGenerateKey) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	p.logger = targetLogger.Named(PKIKeyGenerationTestType)

	mountPath, err := resolveMountPath(mountName, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}
	p.logger = p.logger.Named(mountPath)

	p.logger.Trace(mountLogMessage("secrets", "pki", mountPath))
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting pki secrets engine: %v", err)
	}
	p.mountPath = mountPath

	// Brief delay to let the PKI mount finish initialising before the first
	// write — mirrors the pattern used by pki_issue and pki_sign.
	delay, err := time.ParseDuration(p.config.SetupDelay)
	if err != nil {
		return nil, fmt.Errorf("error parsing setup_delay: %v", err)
	}
	time.Sleep(delay)

	p.logger.Trace(parsingConfigLogMessage("generate key"))
	bodyData, err := structToMap(p.config.GenerateKeyConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing generate_key config: %v", err)
	}
	// "type" is the URL path segment, not a body field.
	delete(bodyData, "type")

	bodyBytes, err := json.Marshal(bodyData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling generate_key config: %v", err)
	}

	keyGenType := p.config.GenerateKeyConfig.Type
	if keyGenType == "" {
		keyGenType = "internal"
	}

	return &PKIGenerateKey{
		// POST /v1/<mount>/keys/generate/<type>  where <type> is "internal" or "exported"
		pathPrefix: "/v1/" + filepath.Join(mountPath, "keys", "generate", keyGenType),
		header:     generateHeader(client),
		body:       bodyBytes,
		config:     p.config,
		logger:     p.logger,
		mountPath:  p.mountPath,
	}, nil
}

func (p *PKIGenerateKey) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: PKIKeyGenerationTestMethod,
		URL:    client.Address() + p.pathPrefix,
		Body:   p.body,
		Header: p.header,
	}
}

func (p *PKIGenerateKey) Cleanup(client *api.Client) error {
	return cleanupMount(p.logger, client, "/v1/"+p.mountPath)
}

func (p *PKIGenerateKey) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     PKIKeyGenerationTestMethod,
		pathPrefix: p.pathPrefix,
	}
}

func (p *PKIGenerateKey) Flags(fs *flag.FlagSet) {}
