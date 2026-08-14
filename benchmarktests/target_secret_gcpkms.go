// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	GCPKMSEncryptTestType   = "gcpkms_encrypt"
	GCPKMSDecryptTestType   = "gcpkms_decrypt"
	GCPKMSSignTestType      = "gcpkms_sign"
	GCPKMSVerifyTestType    = "gcpkms_verify"
	GCPKMSReencryptTestType = "gcpkms_reencrypt"
	GCPKMSTestMethod        = "POST"
	GCPKMSCredentials       = VaultBenchmarkEnvVarPrefix + "GCPKMS_CREDENTIALS"
)

func init() {
	TestList[GCPKMSEncryptTestType] = func() BenchmarkBuilder {
		return &GCPKMSSecret{action: "encrypt", typeKey: GCPKMSEncryptTestType}
	}
	TestList[GCPKMSDecryptTestType] = func() BenchmarkBuilder {
		return &GCPKMSSecret{action: "decrypt", typeKey: GCPKMSDecryptTestType}
	}
	TestList[GCPKMSSignTestType] = func() BenchmarkBuilder {
		return &GCPKMSSecret{action: "sign", typeKey: GCPKMSSignTestType}
	}
	TestList[GCPKMSVerifyTestType] = func() BenchmarkBuilder {
		return &GCPKMSSecret{action: "verify", typeKey: GCPKMSVerifyTestType}
	}
	TestList[GCPKMSReencryptTestType] = func() BenchmarkBuilder {
		return &GCPKMSSecret{action: "reencrypt", typeKey: GCPKMSReencryptTestType}
	}
}

type GCPKMSSecret struct {
	pathPrefix string
	header     http.Header
	body       []byte
	action     string
	typeKey    string
	mountPath  string
	config     *GCPKMSSecretConfig
	logger     hclog.Logger
}

type GCPKMSSecretConfig struct {
	PayloadLen            int                    `hcl:"payload_len,optional"`
	GCPKMSSecretMountConfig          *GCPKMSSecretMountConfig          `hcl:"config,block"`
	GCPKMSSecretKeyConfig       *GCPKMSSecretKeyConfig       `hcl:"key,block"`
	GCPKMSSecretEncryptConfig   *GCPKMSSecretEncryptConfig   `hcl:"encrypt,block"`
	GCPKMSSecretDecryptConfig   *GCPKMSSecretDecryptConfig   `hcl:"decrypt,block"`
	GCPKMSSecretSignConfig      *GCPKMSSecretSignConfig      `hcl:"sign,block"`
	GCPKMSSecretVerifyConfig    *GCPKMSSecretVerifyConfig    `hcl:"verify,block"`
	GCPKMSSecretReencryptConfig *GCPKMSSecretReencryptConfig `hcl:"reencrypt,block"`
}

type GCPKMSSecretMountConfig struct {
	Credentials string   `hcl:"credentials,optional"`
	Scopes      []string `hcl:"scopes,optional"`
}

type GCPKMSSecretKeyConfig struct {
	Key             string            `hcl:"key,optional"`
	KeyRing         string            `hcl:"key_ring"`
	CryptoKey       string            `hcl:"crypto_key,optional"`
	Purpose         string            `hcl:"purpose,optional"`
	Algorithm       string            `hcl:"algorithm,optional"`
	ProtectionLevel string            `hcl:"protection_level,optional"`
	RotationPeriod  string            `hcl:"rotation_period,optional"`
	Labels          map[string]string `hcl:"labels,optional"`
	Mode            string            `hcl:"mode,optional"` // "create" (default) or "register"
}

type GCPKMSSecretEncryptConfig struct {
	Plaintext                   string `hcl:"plaintext,optional"`
	AdditionalAuthenticatedData string `hcl:"additional_authenticated_data,optional"`
}

type GCPKMSSecretDecryptConfig struct {
	Ciphertext                  string `hcl:"ciphertext,optional"`
	AdditionalAuthenticatedData string `hcl:"additional_authenticated_data,optional"`
}

type GCPKMSSecretSignConfig struct {
	KeyVersion int    `hcl:"key_version,optional"`
	Digest     string `hcl:"digest,optional"`
}

type GCPKMSSecretVerifyConfig struct {
	KeyVersion int    `hcl:"key_version,optional"`
	Digest     string `hcl:"digest,optional"`
	Signature  string `hcl:"signature,optional"`
}

type GCPKMSSecretReencryptConfig struct {
	Ciphertext                  string `hcl:"ciphertext,optional"`
	AdditionalAuthenticatedData string `hcl:"additional_authenticated_data,optional"`
}

func (g *GCPKMSSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPKMSSecretConfig `hcl:"config,block"`
	}{
		Config: &GCPKMSSecretConfig{
			GCPKMSSecretMountConfig: &GCPKMSSecretMountConfig{
				Credentials: os.Getenv(GCPKMSCredentials),
				Scopes:      []string{"https://www.googleapis.com/auth/cloudkms"},
			},
			GCPKMSSecretKeyConfig: &GCPKMSSecretKeyConfig{
				Key:             "benchmark-key",
				Purpose:         "encrypt_decrypt",
				Algorithm:       "symmetric_encryption",
				ProtectionLevel: "software",
				Mode:            "create",
			},
			GCPKMSSecretEncryptConfig: &GCPKMSSecretEncryptConfig{},
			GCPKMSSecretDecryptConfig: &GCPKMSSecretDecryptConfig{},
			GCPKMSSecretSignConfig: &GCPKMSSecretSignConfig{
				KeyVersion: 1,
			},
			GCPKMSSecretVerifyConfig: &GCPKMSSecretVerifyConfig{
				KeyVersion: 1,
			},
			GCPKMSSecretReencryptConfig: &GCPKMSSecretReencryptConfig{},
			PayloadLen:            128,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	g.config = testConfig.Config

	if g.config.GCPKMSSecretMountConfig.Credentials == "" {
		return fmt.Errorf("GCP KMS credentials are required")
	}

	if g.config.GCPKMSSecretKeyConfig.KeyRing == "" {
		return fmt.Errorf("GCP KMS key ring is required")
	}

	return nil
}

func (g *GCPKMSSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName

	g.logger = targetLogger.Named(g.typeKey)

	secretPath, err = resolveMountPath(secretPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	g.logger.Trace(mountLogMessage("secrets", "gcpkms", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "gcpkms",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting gcpkms backend: %v", err)
	}

	setupLogger := g.logger.Named(secretPath)

	creds := g.config.GCPKMSSecretMountConfig.Credentials
	if len(creds) > 0 && creds[0] == '@' {
		contents, err := os.ReadFile(creds[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading credentials file: %w", err)
		}
		g.config.GCPKMSSecretMountConfig.Credentials = string(contents)
	}

	setupLogger.Trace(parsingConfigLogMessage("gcpkms config"))
	configData, err := structToMap(g.config.GCPKMSSecretMountConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcpkms config from struct: %v", err)
	}

	setupLogger.Trace(writingLogMessage("gcpkms config"))
	_, err = client.Logical().Write(filepath.Join(secretPath, "config"), configData)
	if err != nil {
		return nil, fmt.Errorf("error writing gcpkms config: %v", err)
	}

	if err := g.createKey(client, secretPath, g.config.GCPKMSSecretKeyConfig, setupLogger); err != nil {
		return nil, err
	}

	setupLogger.Trace("generating test payload")
	rawPayload, err := uuid.GenerateRandomBytes(g.config.PayloadLen)
	if err != nil {
		return nil, fmt.Errorf("error generating random payload: %v", err)
	}
	base64Payload := base64.StdEncoding.EncodeToString(rawPayload)

	keyName := g.config.GCPKMSSecretKeyConfig.Key

	switch g.action {
	case "encrypt":
		g.config.GCPKMSSecretEncryptConfig.Plaintext = base64Payload
		encryptData, err := structToMap(g.config.GCPKMSSecretEncryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms encrypt config from struct: %v", err)
		}
		return g.buildResult(client, secretPath, "encrypt", keyName, encryptData)

	case "decrypt":
		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", keyName), map[string]any{"plaintext": base64Payload})
		if err != nil {
			return nil, fmt.Errorf("error encrypting payload: %v", err)
		}
		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt payload: no response or invalid ciphertext: %v", resp)
		}
		g.config.GCPKMSSecretDecryptConfig.Ciphertext = resp.Data["ciphertext"].(string)
		decryptData, err := structToMap(g.config.GCPKMSSecretDecryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms decrypt config from struct: %v", err)
		}
		return g.buildResult(client, secretPath, "decrypt", keyName, decryptData)

	case "sign":
		g.config.GCPKMSSecretSignConfig.Digest = base64.StdEncoding.EncodeToString(rawPayload)
		signData, err := structToMap(g.config.GCPKMSSecretSignConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms sign config from struct: %v", err)
		}
		return g.buildResult(client, secretPath, "sign", keyName, signData)

	case "verify":
		digest := base64.StdEncoding.EncodeToString(rawPayload)
		resp, err := client.Logical().Write(filepath.Join(secretPath, "sign", keyName), map[string]any{
			"digest":      digest,
			"key_version": g.config.GCPKMSSecretVerifyConfig.KeyVersion,
		})
		if err != nil {
			return nil, fmt.Errorf("error signing digest: %v", err)
		}
		if resp == nil || resp.Data["signature"] == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign digest: no response or invalid signature: %v", resp)
		}
		g.config.GCPKMSSecretVerifyConfig.Digest = digest
		g.config.GCPKMSSecretVerifyConfig.Signature = resp.Data["signature"].(string)
		verifyData, err := structToMap(g.config.GCPKMSSecretVerifyConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms verify config from struct: %v", err)
		}
		return g.buildResult(client, secretPath, "verify", keyName, verifyData)

	case "reencrypt":
		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", keyName), map[string]any{"plaintext": base64Payload})
		if err != nil {
			return nil, fmt.Errorf("error encrypting payload: %v", err)
		}
		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt payload: no response or invalid ciphertext: %v", resp)
		}
		g.config.GCPKMSSecretReencryptConfig.Ciphertext = resp.Data["ciphertext"].(string)
		reencryptData, err := structToMap(g.config.GCPKMSSecretReencryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms reencrypt config from struct: %v", err)
		}
		return g.buildResult(client, secretPath, "reencrypt", keyName, reencryptData)

	default:
		return nil, fmt.Errorf("unknown or unsupported gcpkms operation: %v", g.action)
	}
}

func (g *GCPKMSSecret) buildResult(client *api.Client, secretPath, action, keyName string, configData map[string]any) (BenchmarkBuilder, error) {
	body, err := json.Marshal(configData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling gcpkms %s data: %v", action, err)
	}
	return &GCPKMSSecret{
		pathPrefix: "/v1/" + filepath.Join(secretPath, action, keyName),
		mountPath:  "/v1/" + secretPath,
		header:     generateHeader(client),
		body:       body,
		logger:     g.logger,
	}, nil
}

// createKey handles key creation or registration based on the configured mode.
// In "create" mode (default), it creates new keys with randomized suffixes to prevent collisions.
// In "register" mode, it registers existing GCP KMS keys without attempting to create them.
// Note: Keys created in GCP KMS are not automatically cleaned up during benchmark cleanup.

func (g *GCPKMSSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GCPKMSTestMethod,
		URL:    client.Address() + g.pathPrefix,
		Body:   g.body,
		Header: g.header,
	}
}

func (g *GCPKMSSecret) Cleanup(client *api.Client) error {
	return cleanupMount(g.logger, client, g.mountPath)
}

func (g *GCPKMSSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPKMSTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPKMSSecret) Flags(fs *flag.FlagSet) {}

func (g *GCPKMSSecret) createKey(client *api.Client, secretPath string, keyConfig *GCPKMSSecretKeyConfig, logger hclog.Logger) error {
	mode := keyConfig.Mode

	logger.Trace(parsingConfigLogMessage("gcpkms key"), "name", keyConfig.Key, "mode", mode)

	if mode == "create" {
		uuid, err := uuid.GenerateUUID()
		if err != nil {
			return fmt.Errorf("error generating UUID for key name: %v", err)
		}

		keyConfig.Key = fmt.Sprintf("%s-%s", keyConfig.Key, uuid[:8])
		keyPath := filepath.Join(secretPath, "keys", keyConfig.Key)

		logger.Trace("adding random suffix to key name", "name", keyConfig.Key)
		return g.createNewKey(client, keyPath, keyConfig, logger)
	} else if mode == "register" {
		return g.registerExistingKey(client, secretPath, keyConfig, logger)
	}

	return fmt.Errorf("invalid key mode: %s (must be 'create' or 'register')", mode)
}

func (g *GCPKMSSecret) createNewKey(client *api.Client, keyPath string, keyConfig *GCPKMSSecretKeyConfig, logger hclog.Logger) error {

	keyConfig.Mode = "" // Exclude mode from API payload

	keyCreateData, err := structToMap(keyConfig)
	if err != nil {
		return fmt.Errorf("error parsing gcpkms key config from struct: %v", err)
	}

	logger.Trace(writingLogMessage("gcpkms key creation"), "name", keyConfig.Key)
	_, err = client.Logical().Write(keyPath, keyCreateData)
	if err != nil {
		return fmt.Errorf("error creating gcpkms key: %v", err)
	}
	logger.Trace("successfully created new key", "name", keyConfig.Key)
	return nil
}

func (g *GCPKMSSecret) registerExistingKey(client *api.Client, secretPath string, keyConfig *GCPKMSSecretKeyConfig, logger hclog.Logger) error {
	if keyConfig.CryptoKey == "" {
		keyConfig.CryptoKey = keyConfig.Key
	}

	fullCryptoKeyID := fmt.Sprintf("%s/cryptoKeys/%s", keyConfig.KeyRing, keyConfig.CryptoKey)

	registerData := map[string]any{
		"crypto_key": fullCryptoKeyID,
		"verify":     true,
	}

	registerPath := filepath.Join(secretPath, "keys", "register", keyConfig.CryptoKey)
	logger.Trace(writingLogMessage("gcpkms key registration"), "name", keyConfig.CryptoKey, "crypto_key", fullCryptoKeyID)
	_, err := client.Logical().Write(registerPath, registerData)
	if err != nil {
		return fmt.Errorf("error registering gcpkms key: %v", err)
	}
	logger.Trace("successfully registered existing key", "name", keyConfig.CryptoKey)
	return nil
}
