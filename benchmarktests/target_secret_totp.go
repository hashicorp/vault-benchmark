// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

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
	TestList[TOTPSecretCreateTestType] = func() BenchmarkBuilder {
		return &TOTPSecret{action: "create", typeKey: TOTPSecretCreateTestType}
	}
	TestList[TOTPSecretReadTestType] = func() BenchmarkBuilder {
		return &TOTPSecret{action: "read", typeKey: TOTPSecretReadTestType}
	}
	TestList[TOTPSecretGenerateTestType] = func() BenchmarkBuilder {
		return &TOTPSecret{action: "generate", typeKey: TOTPSecretGenerateTestType}
	}
}

type TOTPSecret struct {
	pathPrefix        string
	header            http.Header
	baseURL           string
	createKeyDataJSON []byte
	action            string
	typeKey          string
	config            *TOTPSecretConfig
	logger            hclog.Logger
	mountPath         string
}

type TOTPSecretConfig struct {
	KeyName     string `hcl:"key_name"`
	Issuer      string `hcl:"issuer"`
	AccountName string `hcl:"account_name"`
	Algorithm   string `hcl:"algorithm,optional"`
	Digits      int    `hcl:"digits,optional"`
	Period      int    `hcl:"period,optional"`
	Generate    bool   `hcl:"generate,optional"`
}

func (t *TOTPSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TOTPSecretConfig `hcl:"config,block"`
	}{
		Config: &TOTPSecretConfig{
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

func (t *TOTPSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName

	t.logger = targetLogger.Named(t.typeKey)

	mountPath, err = resolveMountPath(mountPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	setupLogger := t.logger.Named("totp")

	setupLogger.Trace("mounting TOTP secrets engine", "path", mountPath)
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "totp",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting TOTP secrets engine: %v", err)
	}

	keyName := t.config.KeyName
	if topLevelConfig.RandomMounts {
		randomSuffix, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("error generating random mount name: %w", err)
		}
		keyName = fmt.Sprintf("%s-%s", t.config.KeyName, randomSuffix)
	}

	keyData := map[string]any{
		"generate":     t.config.Generate,
		"issuer":       t.config.Issuer,
		"account_name": t.config.AccountName,
		"algorithm":    t.config.Algorithm,
		"digits":       t.config.Digits,
		"period":       t.config.Period,
	}

	if t.action == "generate" || t.action == "read" {
		setupLogger.Trace("creating TOTP key for operations", "key", keyName, "action", t.action)

		_, err := client.Logical().Write(fmt.Sprintf("%s/keys/%s", mountPath, keyName), keyData)
		if err != nil {
			return nil, fmt.Errorf("error creating TOTP key %s: %v", keyName, err)
		}
	}

	configCopy := *t.config
	configCopy.KeyName = keyName

	baseURL := fmt.Sprintf("%s/v1/%s", client.Address(), mountPath)

	createKeyData := map[string]any{
		"generate":     true,
		"issuer":       configCopy.Issuer,
		"account_name": configCopy.AccountName,
	}
	createKeyDataJSON, _ := json.Marshal(createKeyData)

	return &TOTPSecret{
		pathPrefix:        "/v1/" + mountPath,
		header:            http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		action:            t.action,
		typeKey:          t.typeKey,
		config:            &configCopy,
		logger:            t.logger,
		baseURL:           baseURL,
		mountPath:         mountPath,
		createKeyDataJSON: createKeyDataJSON,
	}, nil
}

func (t *TOTPSecret) Target(client *api.Client) vegeta.Target {
	tgt := vegeta.Target{
		Method: TOTPSecretTestMethod,
		URL:    t.baseURL + "/keys/" + t.config.KeyName,
		Header: t.header,
	}
	switch t.action {
	case "create":
		tgt.Method = TOTPSecretCreateTestMethod
		tgt.URL = t.baseURL + "/keys/" + t.config.KeyName + "-" + strconv.FormatInt(rand.Int63(), 36)
		tgt.Body = t.createKeyDataJSON
	case "generate":
		tgt.URL = t.baseURL + "/code/" + t.config.KeyName
	}
	return tgt
}

func (t *TOTPSecret) Cleanup(client *api.Client) error {
	t.logger.Trace(cleanupLogMessage(t.pathPrefix))

	err := client.Sys().Unmount(t.mountPath)
	if err != nil {
		return fmt.Errorf("error unmounting TOTP secrets engine at %s: %v", t.mountPath, err)
	}

	t.logger.Trace("successfully cleaned up TOTP mount", "path", t.mountPath)
	return nil
}

func (t *TOTPSecret) GetTargetInfo() TargetInfo {
	method := TOTPSecretTestMethod
	if t.action == "create" {
		method = TOTPSecretCreateTestMethod
	}
	return TargetInfo{
		method:     method,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TOTPSecret) Flags(fs *flag.FlagSet) {}
