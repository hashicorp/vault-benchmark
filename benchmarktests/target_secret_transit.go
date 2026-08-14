// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	TransitSignSecretTestType    = "transit_sign"
	TransitVerifySecretTestType  = "transit_verify"
	TransitEncryptSecretTestType = "transit_encrypt"
	TransitDecryptSecretTestType = "transit_decrypt"
	TransitSecretTestMethod      = "POST"
)

func init() {
	TestList[TransitSignSecretTestType] = func() BenchmarkBuilder {
		return &TransitSecret{action: "sign", typeKey: TransitSignSecretTestType}
	}
	TestList[TransitVerifySecretTestType] = func() BenchmarkBuilder {
		return &TransitSecret{action: "verify", typeKey: TransitVerifySecretTestType}
	}
	TestList[TransitEncryptSecretTestType] = func() BenchmarkBuilder {
		return &TransitSecret{action: "encrypt", typeKey: TransitEncryptSecretTestType}
	}
	TestList[TransitDecryptSecretTestType] = func() BenchmarkBuilder {
		return &TransitSecret{action: "decrypt", typeKey: TransitDecryptSecretTestType}
	}
}

type TransitSecret struct {
	pathPrefix string
	header     http.Header
	body       []byte
	action     string
	typeKey    string
	mountPath  string
	config     *TransitSecretConfig
	logger     hclog.Logger
}

type TransitSecretConfig struct {
	PayloadLen           int                   `hcl:"payload_len,optional"`
	ContextLen           int                   `hcl:"context_len,optional"`
	TransitKeysConfig    *TransitKeysConfig    `hcl:"keys,block"`
	TransitSignConfig    *TransitSignConfig    `hcl:"sign,block"`
	TransitVerifyConfig  *TransitVerifyConfig  `hcl:"verify,block"`
	TransitEncryptConfig *TransitEncryptConfig `hcl:"encrypt,block"`
	TransitDecryptConfig *TransitDecryptConfig `hcl:"decrypt,block"`
}

// /transit/keys/:name
type TransitKeysConfig struct {
	Name                 string `hcl:"name,optional"`
	ConvergentEncryption bool   `hcl:"convergent_encryption,optional"`
	Derived              bool   `hcl:"derived,optional"`
	Exportable           bool   `hcl:"exportable,optional"`
	AllowPlaintextBackup bool   `hcl:"allow_plaintext_backup,optional"`
	Type                 string `hcl:"type,optional"`
	KeySize              int    `hcl:"key_size,optional"`
	AutoRotatePeriod     string `hcl:"auto_rotate_period,optional"`
	ManagedKeyName       string `hcl:"managed_key_name,optional"`
	ManagedKeyID         string `hcl:"managed_key_id,optional"`
	ParameterSet         string `hcl:"parameter_set,optional"`
	HybridKeyTypeEC      string `hcl:"hybrid_key_type_ec,optional"`
	HybridKeyTypePQC     string `hcl:"hybrid_key_type_pqc,optional"`
}

// /transit/sign/:name
type TransitSignConfig struct {
	Name                string `hcl:"name,optional"`
	KeyVersion          int    `hcl:"key_version,optional"`
	HashAlgorithm       string `hcl:"hash_algorithm,optional"`
	Input               string `hcl:"input,optional"`
	Reference           string `hcl:"reference,optional"`
	BatchInput          []any  `hcl:"batch_input,optional"`
	Context             string `hcl:"context,optional"`
	Prehashed           bool   `hcl:"prehashed,optional"`
	SignatureAlgorithm  string `hcl:"signature_algorithm,optional"`
	MarshalingAlgorithm string `hcl:"marshaling_algorithm,optional"`
	SaltLength          string `hcl:"salt_length,optional"`
}

// /transit/verify/:name(/:hash_algorithm)
type TransitVerifyConfig struct {
	Name                string `hcl:"name,optional"`
	HashAlgorithm       string `hcl:"hash_algorithm,optional"`
	Input               string `hcl:"input,optional"`
	Signature           string `hcl:"signature,optional"`
	HMAC                string `hcl:"hmac,optional"`
	Reference           string `hcl:"reference,optional"`
	BatchInput          []any  `hcl:"batch_input,optional"`
	Context             string `hcl:"context,optional"`
	Prehashed           bool   `hcl:"prehashed,optional"`
	SignatureAlgorithm  string `hcl:"signature_algorithm,optional"`
	MarshalingAlgorithm string `hcl:"marshaling_algorithm,optional"`
	SaltLength          string `hcl:"salt_length,optional"`
}

// /transit/encrypt/:name
type TransitEncryptConfig struct {
	Name                       string `hcl:"name,optional"`
	Plaintext                  string `hcl:"plaintext,optional"`
	AssociatedData             string `hcl:"associated_data,optional"`
	Context                    string `hcl:"context,optional"`
	KeyVersion                 int    `hcl:"key_version,optional"`
	Nonce                      string `hcl:"nonce,optional"`
	Reference                  string `hcl:"reference,optional"`
	BatchInput                 []any  `hcl:"batch_input,optional"`
	Type                       string `hcl:"type,optional"`
	ConvergentEncryption       bool   `hcl:"convergent_encryption,optional"`
	PartialFailureResponseCode int    `hcl:"partial_failure_response_code,optional"`
}

// /transit/decrypt/:name
type TransitDecryptConfig struct {
	Name                       string `hcl:"name,optional"`
	Ciphertext                 string `hcl:"ciphertext,optional"`
	AssociatedData             string `hcl:"associated_data,optional"`
	Context                    string `hcl:"context,optional"`
	Nonce                      string `hcl:"nonce,optional"`
	Reference                  string `hcl:"reference,optional"`
	BatchInput                 []any  `hcl:"batch_input,optional"`
	PartialFailureResponseCode int    `hcl:"partial_failure_response_code,optional"`
}

func (t *TransitSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *TransitSecretConfig `hcl:"config,block"`
	}{
		Config: &TransitSecretConfig{
			TransitKeysConfig: &TransitKeysConfig{
				Name:                 "test",
				ConvergentEncryption: false,
				Derived:              false,
				Type:                 "rsa-2048",
			},
			TransitSignConfig: &TransitSignConfig{
				Name:                "test",
				HashAlgorithm:       "sha2-256",
				SignatureAlgorithm:  "pss",
				MarshalingAlgorithm: "asn1",
			},
			TransitVerifyConfig: &TransitVerifyConfig{
				Name:                "test",
				HashAlgorithm:       "sha2-256",
				SignatureAlgorithm:  "pss",
				MarshalingAlgorithm: "asn1",
			},
			TransitEncryptConfig: &TransitEncryptConfig{
				Name: "test",
			},
			TransitDecryptConfig: &TransitDecryptConfig{
				Name: "test",
			},
			PayloadLen: 128,
			ContextLen: 32,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	t.config = testConfig.Config

	return nil
}

func (t *TransitSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	t.logger = targetLogger.Named(t.typeKey)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	t.logger.Trace(mountLogMessage("secrets", "transit", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "transit",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting transit backend: %v", err)
	}

	setupLogger := t.logger.Named(secretPath)
	setupLogger.Trace(parsingConfigLogMessage("transit key"))
	keysConfigData, err := structToMap(t.config.TransitKeysConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing transit key config from struct: %v", err)
	}

	setupLogger.Trace(writingLogMessage("key config"), "name", t.config.TransitKeysConfig.Name)
	_, err = client.Logical().Write(filepath.Join(secretPath, "keys", t.config.TransitKeysConfig.Name), keysConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing transit key config: %v", err)
	}

	setupLogger.Trace("generating test payload and context")
	rawPayload, err := uuid.GenerateRandomBytes(t.config.PayloadLen)
	if err != nil {
		return nil, fmt.Errorf("error generating random payload: %v", err)
	}
	base64Payload := base64.StdEncoding.EncodeToString(rawPayload)

	rawContext, err := uuid.GenerateRandomBytes(t.config.ContextLen)
	if err != nil {
		return nil, fmt.Errorf("error generating random context: %v", err)
	}
	base64Context := base64.StdEncoding.EncodeToString(rawContext)

	switch t.action {
	case "sign":
		signConfigData, err := structToMap(t.config.TransitSignConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing sign config from struct: %v", err)
		}
		return t.buildResult(client, secretPath, "sign", t.config.TransitSignConfig.Name, signConfigData)

	case "verify":
		signData, err := structToMap(t.config.TransitVerifyConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit verify config from struct: %v", err)
		}
		resp, err := client.Logical().Write(filepath.Join(secretPath, "sign", t.config.TransitVerifyConfig.Name), signData)
		if err != nil {
			return nil, fmt.Errorf("error signing payload: %v", err)
		}
		if resp == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign payload: no response or invalid signature: %v", resp)
		}
		t.config.TransitVerifyConfig.Signature = resp.Data["signature"].(string)
		verifyData, err := structToMap(t.config.TransitVerifyConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit verify config from struct: %v", err)
		}
		return t.buildResult(client, secretPath, "verify", t.config.TransitVerifyConfig.Name, verifyData)

	case "encrypt":
		if t.config.TransitKeysConfig.Derived {
			t.config.TransitEncryptConfig.Context = base64Context
		}
		t.config.TransitEncryptConfig.Plaintext = base64Payload
		encryptData, err := structToMap(t.config.TransitEncryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit encrypt config from struct: %v", err)
		}
		return t.buildResult(client, secretPath, "encrypt", t.config.TransitEncryptConfig.Name, encryptData)

	case "decrypt":
		seedData := map[string]any{"plaintext": base64Payload}
		if t.config.TransitKeysConfig.Derived {
			t.config.TransitDecryptConfig.Context = base64Context
			seedData["context"] = base64Context
		}
		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", t.config.TransitDecryptConfig.Name), seedData)
		if err != nil {
			return nil, fmt.Errorf("error encrypting payload: %v", err)
		}
		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt payload: no response or invalid ciphertext: %v", resp)
		}
		t.config.TransitDecryptConfig.Ciphertext = resp.Data["ciphertext"].(string)
		decryptData, err := structToMap(t.config.TransitDecryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit decrypt config: %v", err)
		}
		return t.buildResult(client, secretPath, "decrypt", t.config.TransitDecryptConfig.Name, decryptData)

	default:
		return nil, fmt.Errorf("unknown or unsupported transit operation: %v", t.action)
	}
}

func (t *TransitSecret) buildResult(client *api.Client, secretPath, action, keyName string, configData map[string]any) (BenchmarkBuilder, error) {
	body, err := json.Marshal(configData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling transit %s data: %v", action, err)
	}
	return &TransitSecret{
		pathPrefix: "/v1/" + filepath.Join(secretPath, action, keyName),
		mountPath:  "/v1/" + secretPath,
		header:     generateHeader(client),
		body:       body,
		logger:     t.logger,
	}, nil
}

func (t *TransitSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: TransitSecretTestMethod,
		URL:    client.Address() + t.pathPrefix,
		Body:   t.body,
		Header: t.header,
	}
}

func (t *TransitSecret) Cleanup(client *api.Client) error {
	return cleanupMount(t.logger, client, t.mountPath)
}

func (t *TransitSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     TransitSecretTestMethod,
		pathPrefix: t.pathPrefix,
	}
}

func (t *TransitSecret) Flags(fs *flag.FlagSet) {}
