// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
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

// Constants for TOTP test types
const (
	TOTPSecretCreateTestType   = "totp_create"
	TOTPSecretGenerateTestType = "totp_generate"
	TOTPSecretReadTestType     = "totp_read"
	TOTPSecretCreateTestMethod = "POST"
	TOTPSecretTestMethod       = "GET"
	TOTPPathPrefix             = "/v1/totp"
	DefaultKeyName             = "benchmark-key"
	DefaultIssuer              = "Vault Benchmark"
	DefaultAccountName         = "test@user.com"
	DefaultAlgorithm           = "SHA1"
	DefaultDigits              = 6
	DefaultPeriod              = 30
)

func init() {
	// Register these tests to the main test registry
	TestList[TOTPSecretCreateTestType] = func() BenchmarkBuilder {
		return &TOTPSecretTest{action: "create"}
	}
	TestList[TOTPSecretReadTestType] = func() BenchmarkBuilder {
		return &TOTPSecretTest{action: "read"}
	}
	TestList[TOTPSecretGenerateTestType] = func() BenchmarkBuilder {
		return &TOTPSecretTest{action: "generate"}
	}
}

type TOTPSecretTest struct {
	pathPrefix        string
	header            http.Header
	config            *TOTPSecretTestConfig
	action            string
	logger            hclog.Logger
	baseURL           string
	mountPath         string
	keyIndex          int    // Current key index
	createKeyDataJSON []byte // Pre-marshaled JSON for key creation
}

type TOTPSecretTestConfig struct {
	KeyName     string `hcl:"key_name"`
	Issuer      string `hcl:"issuer"`
	AccountName string `hcl:"account_name"`
	Algorithm   string `hcl:"algorithm,optional"`
	Digits      int    `hcl:"digits,optional"`
	Period      int    `hcl:"period,optional"`
	Generate    bool   `hcl:"generate,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during testing
func (t *TOTPSecretTest) ParseConfig(body hcl.Body) error {
	// provide defaults
	testConfig := &struct {
		Config *TOTPSecretTestConfig `hcl:"config,block"`
	}{
		Config: &TOTPSecretTestConfig{
			KeyName:     DefaultKeyName,
			Issuer:      DefaultIssuer,
			AccountName: DefaultAccountName,
			Algorithm:   DefaultAlgorithm,
			Digits:      DefaultDigits,
			Period:      DefaultPeriod,
			Generate:    true,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	t.config = testConfig.Config
	if t.config.KeyName == "" {
		t.config.KeyName = DefaultKeyName
	}
	return nil
}

func (t *TOTPSecretTest) create() vegeta.Target {
	// Optimization: Use index-based naming for unique keys
	keyName := fmt.Sprintf("%s-shared-%d", t.config.KeyName, t.keyIndex)
	t.keyIndex++

	return vegeta.Target{
		Method: TOTPSecretCreateTestMethod,
		URL:    t.baseURL + "/keys/" + keyName,
		Header: t.header,
		Body:   t.createKeyDataJSON, // Use pre-marshaled JSON
	}
}

func (t *TOTPSecretTest) generate() vegeta.Target {
	// Use the base key name for generate operations
	keyName := t.config.KeyName

	return vegeta.Target{
		Method: TOTPSecretTestMethod,
		URL:    t.baseURL + "/code/" + keyName,
		Header: t.header,
	}
}

func (t *TOTPSecretTest) read() vegeta.Target {
	// Use the base key name for read operations
	keyName := t.config.KeyName

	return vegeta.Target{
		Method: TOTPSecretTestMethod,
		URL:    t.baseURL + "/keys/" + keyName,
		Header: t.header,
	}
}

func (t *TOTPSecretTest) Target(client *api.Client) vegeta.Target {
	switch t.action {
	case "create":
		return t.create()
	case "generate":
		return t.generate()
	case "read":
		return t.read()
	default:
		return t.create()
	}
}

func (t *TOTPSecretTest) GetTargetInfo() TargetInfo {
	method := TOTPSecretTestMethod
	if t.action == "create" {
		method = TOTPSecretCreateTestMethod
	}
	return TargetInfo{
		method:     method,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TOTPSecretTest) Cleanup(client *api.Client) error {
	t.logger.Trace(cleanupLogMessage(t.pathPrefix))

	// Clean up the mount itself (this will clean up all keys in the mount)
	err := client.Sys().Unmount(t.mountPath)
	if err != nil {
		return fmt.Errorf("error unmounting TOTP secrets engine at %s: %v", t.mountPath, err)
	}

	t.logger.Trace("successfully cleaned up TOTP mount", "path", t.mountPath)
	return nil
}

func (t *TOTPSecretTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName

	switch t.action {
	case "create":
		t.logger = targetLogger.Named(TOTPSecretCreateTestType)
	case "read":
		t.logger = targetLogger.Named(TOTPSecretReadTestType)
	case "generate":
		t.logger = targetLogger.Named(TOTPSecretGenerateTestType)
	default:
		t.logger = targetLogger.Named(TOTPSecretCreateTestType)
	}

	if topLevelConfig.RandomMounts {
		mountPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	setupLogger := t.logger.Named("totp")

	// Enable TOTP secrets engine
	setupLogger.Trace("mounting TOTP secrets engine", "path", mountPath)
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "totp",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting TOTP secrets engine: %v", err)
	}

	// Generate a unique key name if randomization is requested
	keyName := t.config.KeyName
	if topLevelConfig.RandomMounts {
		randomSuffix, err := uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
		keyName = fmt.Sprintf("%s-%s", t.config.KeyName, randomSuffix)
	}

	// Prepare key data for TOTP operations
	keyData := map[string]interface{}{
		"generate":     t.config.Generate,
		"issuer":       t.config.Issuer,
		"account_name": t.config.AccountName,
		"algorithm":    t.config.Algorithm,
		"digits":       t.config.Digits,
		"period":       t.config.Period,
	}

	// Create keys for operations that need to read existing keys
	if t.action == "generate" || t.action == "read" {
		setupLogger.Trace("creating TOTP key for operations", "key", keyName, "action", t.action)

		_, err := client.Logical().Write(fmt.Sprintf("%s/keys/%s", mountPath, keyName), keyData)
		if err != nil {
			return nil, fmt.Errorf("error creating TOTP key %s: %v", keyName, err)
		}
	}

	// Update the config with the potentially randomized key name
	configCopy := *t.config
	configCopy.KeyName = keyName

	// Pre-compute base URL for performance optimization
	baseURL := fmt.Sprintf("%s/v1/%s", client.Address(), mountPath)

	// Optimization: Pre-marshal JSON for create operations (simplified keyData for creation)
	createKeyData := map[string]interface{}{
		"generate":     true,
		"issuer":       configCopy.Issuer,
		"account_name": configCopy.AccountName,
	}
	createKeyDataJSON, _ := json.Marshal(createKeyData)

	return &TOTPSecretTest{
		pathPrefix: "/v1/" + mountPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		action:     t.action,
		config:     &configCopy,
		logger:     t.logger,
		baseURL:    baseURL,
		mountPath:  mountPath,
		keyIndex:   0,
		// Optimization: Pre-compute URL patterns to avoid sprintf in hot path]
		createKeyDataJSON: createKeyDataJSON,
	}, nil
}

func (t *TOTPSecretTest) Flags(fs *flag.FlagSet) {}
