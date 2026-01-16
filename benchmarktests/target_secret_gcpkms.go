// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	// "Register" this test to the main test registry
	TestList[GCPKMSEncryptTestType] = func() BenchmarkBuilder { return &GCPKMSTest{action: "encrypt"} }
	TestList[GCPKMSDecryptTestType] = func() BenchmarkBuilder { return &GCPKMSTest{action: "decrypt"} }
	TestList[GCPKMSSignTestType] = func() BenchmarkBuilder { return &GCPKMSTest{action: "sign"} }
	TestList[GCPKMSVerifyTestType] = func() BenchmarkBuilder { return &GCPKMSTest{action: "verify"} }
	TestList[GCPKMSReencryptTestType] = func() BenchmarkBuilder { return &GCPKMSTest{action: "reencrypt"} }
}

type GCPKMSTest struct {
	action     string
	pathPrefix string
	body       []byte
	header     http.Header
	config     *GCPKMSTestConfig
	logger     hclog.Logger
}

type GCPKMSTestConfig struct {
	PayloadLen            int                    `hcl:"payload_len,optional"`
	GCPKMSConfig          *GCPKMSConfig          `hcl:"config,block"`
	GCPKMSKeyConfig       *GCPKMSKeyConfig       `hcl:"key,block"`
	GCPKMSEncryptConfig   *GCPKMSEncryptConfig   `hcl:"encrypt,block"`
	GCPKMSDecryptConfig   *GCPKMSDecryptConfig   `hcl:"decrypt,block"`
	GCPKMSSignConfig      *GCPKMSSignConfig      `hcl:"sign,block"`
	GCPKMSVerifyConfig    *GCPKMSVerifyConfig    `hcl:"verify,block"`
	GCPKMSReencryptConfig *GCPKMSReencryptConfig `hcl:"reencrypt,block"`
}

// Configuration for the GCP KMS engine
type GCPKMSConfig struct {
	Credentials string   `hcl:"credentials,optional"`
	Scopes      []string `hcl:"scopes,optional"`
}

// Configuration for creating/managing keys
type GCPKMSKeyConfig struct {
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

// Configuration for encryption operations
type GCPKMSEncryptConfig struct {
	Plaintext                   string `hcl:"plaintext,optional"`
	AdditionalAuthenticatedData string `hcl:"additional_authenticated_data,optional"`
}

// Configuration for decryption operations
type GCPKMSDecryptConfig struct {
	Ciphertext                  string `hcl:"ciphertext,optional"`
	AdditionalAuthenticatedData string `hcl:"additional_authenticated_data,optional"`
}

// Configuration for signing operations
type GCPKMSSignConfig struct {
	KeyVersion int    `hcl:"key_version,optional"`
	Digest     string `hcl:"digest,optional"`
}

// Configuration for verification operations
type GCPKMSVerifyConfig struct {
	KeyVersion int    `hcl:"key_version,optional"`
	Digest     string `hcl:"digest,optional"`
	Signature  string `hcl:"signature,optional"`
}

// Configuration for re-encryption operations
type GCPKMSReencryptConfig struct {
	Ciphertext                  string `hcl:"ciphertext,optional"`
	AdditionalAuthenticatedData string `hcl:"additional_authenticated_data,optional"`
}

func (g *GCPKMSTest) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPKMSTestConfig `hcl:"config,block"`
	}{
		Config: &GCPKMSTestConfig{
			GCPKMSConfig: &GCPKMSConfig{
				Credentials: os.Getenv(GCPKMSCredentials),
				Scopes:      []string{"https://www.googleapis.com/auth/cloudkms"},
			},
			GCPKMSKeyConfig: &GCPKMSKeyConfig{
				Key:             "benchmark-key",
				Purpose:         "encrypt_decrypt",
				Algorithm:       "symmetric_encryption",
				ProtectionLevel: "software",
				Mode:            "create",
			},
			GCPKMSEncryptConfig: &GCPKMSEncryptConfig{},
			GCPKMSDecryptConfig: &GCPKMSDecryptConfig{},
			GCPKMSSignConfig: &GCPKMSSignConfig{
				KeyVersion: 1,
			},
			GCPKMSVerifyConfig: &GCPKMSVerifyConfig{
				KeyVersion: 1,
			},
			GCPKMSReencryptConfig: &GCPKMSReencryptConfig{},
			PayloadLen:            128,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	g.config = testConfig.Config

	// Validate required configuration
	if g.config.GCPKMSConfig.Credentials == "" {
		return fmt.Errorf("GCP KMS credentials are required")
	}

	if g.config.GCPKMSKeyConfig.KeyRing == "" {
		return fmt.Errorf("GCP KMS key ring is required")
	}

	return nil
}

func (g *GCPKMSTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GCPKMSTestMethod,
		URL:    client.Address() + g.pathPrefix,
		Body:   g.body,
		Header: g.header,
	}
}

func (g *GCPKMSTest) Cleanup(client *api.Client) error {
	parts := strings.Split(g.pathPrefix, "/")
	g.logger.Trace(cleanupLogMessage(parts[2]))
	_, err := client.Logical().Delete(fmt.Sprintf("/sys/mounts/%s", parts[2]))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (g *GCPKMSTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPKMSTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPKMSTest) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName

	switch g.action {
	case "encrypt":
		g.logger = targetLogger.Named(GCPKMSEncryptTestType)
	case "decrypt":
		g.logger = targetLogger.Named(GCPKMSDecryptTestType)
	case "sign":
		g.logger = targetLogger.Named(GCPKMSSignTestType)
	case "verify":
		g.logger = targetLogger.Named(GCPKMSVerifyTestType)
	case "reencrypt":
		g.logger = targetLogger.Named(GCPKMSReencryptTestType)
	}

	if topLevelConfig.RandomMounts {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	g.logger.Trace(mountLogMessage("secrets", "gcpkms", secretPath))
	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "gcpkms",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting gcpkms backend: %v", err)
	}

	setupLogger := g.logger.Named(secretPath)

	// Check if the credentials argument should be read from file
	creds := g.config.GCPKMSConfig.Credentials
	if len(creds) > 0 && creds[0] == '@' {
		contents, err := os.ReadFile(creds[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading credentials file: %w", err)
		}
		g.config.GCPKMSConfig.Credentials = string(contents)
	}

	// Configure the GCP KMS backend
	setupLogger.Trace(parsingConfigLogMessage("gcpkms config"))
	configData, err := structToMap(g.config.GCPKMSConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcpkms config from struct: %v", err)
	}

	setupLogger.Trace(writingLogMessage("gcpkms config"))
	_, err = client.Logical().Write(filepath.Join(secretPath, "config"), configData)
	if err != nil {
		return nil, fmt.Errorf("error writing gcpkms config: %v", err)
	}

	// Create keys for the specific operations
	switch g.action {
	case "encrypt", "decrypt", "reencrypt":
		// Create symmetric encryption key
		err := g.createKey(client, secretPath, g.config.GCPKMSKeyConfig, setupLogger)
		if err != nil {
			return nil, err
		}

	case "sign", "verify":
		// Create asymmetric signing key
		err := g.createKey(client, secretPath, g.config.GCPKMSKeyConfig, setupLogger)
		if err != nil {
			return nil, err
		}
	}

	// Generate payload for testing
	setupLogger.Trace("generating test payload")
	rawPayload, err := uuid.GenerateRandomBytes(g.config.PayloadLen)
	if err != nil {
		return nil, fmt.Errorf("error generating random payload: %v", err)
	}
	base64Payload := base64.StdEncoding.EncodeToString(rawPayload)

	keyName := g.config.GCPKMSKeyConfig.Key

	// Now dispatch the operation
	switch g.action {
	case "encrypt":
		g.config.GCPKMSEncryptConfig.Plaintext = base64Payload

		setupLogger.Trace(parsingConfigLogMessage("gcpkms encrypt"))
		encryptData, err := structToMap(g.config.GCPKMSEncryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms encrypt config from struct: %v", err)
		}

		encryptDataString, err := json.Marshal(encryptData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling gcpkms encrypt data: %v", err)
		}

		encryptPath := filepath.Join(secretPath, "encrypt", keyName)
		return &GCPKMSTest{
			pathPrefix: "/v1/" + encryptPath,
			header:     generateHeader(client),
			body:       []byte(encryptDataString),
			logger:     g.logger,
		}, nil

	case "decrypt":
		// First encrypt some data to get ciphertext
		testEncryptData := map[string]interface{}{
			"plaintext": base64Payload,
		}

		setupLogger.Trace("encrypting payload for decrypt test")
		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", keyName), testEncryptData)
		if err != nil {
			return nil, fmt.Errorf("error encrypting payload: %v", err)
		}

		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt payload: no response or invalid ciphertext: %v", resp)
		}

		g.config.GCPKMSDecryptConfig.Ciphertext = resp.Data["ciphertext"].(string)

		setupLogger.Trace(parsingConfigLogMessage("gcpkms decrypt"))
		decryptData, err := structToMap(g.config.GCPKMSDecryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms decrypt config from struct: %v", err)
		}

		decryptDataString, err := json.Marshal(decryptData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling gcpkms decrypt data: %v", err)
		}

		decryptPath := filepath.Join(secretPath, "decrypt", keyName)
		return &GCPKMSTest{
			pathPrefix: "/v1/" + decryptPath,
			header:     generateHeader(client),
			body:       []byte(decryptDataString),
			logger:     g.logger,
		}, nil

	case "sign":
		// Generate a digest for signing
		digest := base64.StdEncoding.EncodeToString(rawPayload)
		g.config.GCPKMSSignConfig.Digest = digest

		setupLogger.Trace(parsingConfigLogMessage("gcpkms sign"))
		signData, err := structToMap(g.config.GCPKMSSignConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms sign config from struct: %v", err)
		}

		signDataString, err := json.Marshal(signData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling gcpkms sign data: %v", err)
		}

		signPath := filepath.Join(secretPath, "sign", keyName)
		return &GCPKMSTest{
			pathPrefix: "/v1/" + signPath,
			header:     generateHeader(client),
			body:       []byte(signDataString),
			logger:     g.logger,
		}, nil

	case "verify":
		// Generate a digest and sign it first
		digest := base64.StdEncoding.EncodeToString(rawPayload)
		g.config.GCPKMSVerifyConfig.Digest = digest

		// Sign the digest
		signData := map[string]interface{}{
			"digest":      digest,
			"key_version": g.config.GCPKMSVerifyConfig.KeyVersion,
		}

		setupLogger.Trace("signing digest for verify test")
		resp, err := client.Logical().Write(filepath.Join(secretPath, "sign", keyName), signData)
		if err != nil {
			return nil, fmt.Errorf("error signing digest: %v", err)
		}

		if resp == nil || resp.Data["signature"] == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign digest: no response or invalid signature: %v", resp)
		}

		g.config.GCPKMSVerifyConfig.Signature = resp.Data["signature"].(string)

		setupLogger.Trace(parsingConfigLogMessage("gcpkms verify"))
		verifyData, err := structToMap(g.config.GCPKMSVerifyConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms verify config from struct: %v", err)
		}

		verifyDataString, err := json.Marshal(verifyData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling gcpkms verify data: %v", err)
		}

		verifyPath := filepath.Join(secretPath, "verify", keyName)
		return &GCPKMSTest{
			pathPrefix: "/v1/" + verifyPath,
			header:     generateHeader(client),
			body:       []byte(verifyDataString),
			logger:     g.logger,
		}, nil

	case "reencrypt":
		// First encrypt some data to get ciphertext
		testEncryptData := map[string]interface{}{
			"plaintext": base64Payload,
		}

		setupLogger.Trace("encrypting payload for reencrypt test")
		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", keyName), testEncryptData)
		if err != nil {
			return nil, fmt.Errorf("error encrypting payload: %v", err)
		}

		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt payload: no response or invalid ciphertext: %v", resp)
		}

		g.config.GCPKMSReencryptConfig.Ciphertext = resp.Data["ciphertext"].(string)

		setupLogger.Trace(parsingConfigLogMessage("gcpkms reencrypt"))
		reencryptData, err := structToMap(g.config.GCPKMSReencryptConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing gcpkms reencrypt config from struct: %v", err)
		}

		reencryptDataString, err := json.Marshal(reencryptData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling gcpkms reencrypt data: %v", err)
		}

		reencryptPath := filepath.Join(secretPath, "reencrypt", keyName)
		return &GCPKMSTest{
			pathPrefix: "/v1/" + reencryptPath,
			header:     generateHeader(client),
			body:       []byte(reencryptDataString),
			logger:     g.logger,
		}, nil

	default:
		return nil, fmt.Errorf("unknown or unsupported gcpkms operation: %v", g.action)
	}
}

// createKey handles key creation or registration based on the configured mode.
// In "create" mode (default), it creates new keys with randomized suffixes to prevent collisions.
// In "register" mode, it registers existing GCP KMS keys without attempting to create them.
// Note: Keys created in GCP KMS are not automatically cleaned up during benchmark cleanup.
func (g *GCPKMSTest) createKey(client *api.Client, secretPath string, keyConfig *GCPKMSKeyConfig, logger hclog.Logger) error {
	mode := keyConfig.Mode

	logger.Trace(parsingConfigLogMessage("gcpkms key"), "name", keyConfig.Key, "mode", mode)

	// Handle create vs register mode
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

func (g *GCPKMSTest) createNewKey(client *api.Client, keyPath string, keyConfig *GCPKMSKeyConfig, logger hclog.Logger) error {

	keyConfig.Mode = "" // Exclude mode from API payload

	// Convert to map
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

func (g *GCPKMSTest) registerExistingKey(client *api.Client, secretPath string, keyConfig *GCPKMSKeyConfig, logger hclog.Logger) error {
	if keyConfig.CryptoKey == "" {
		keyConfig.CryptoKey = keyConfig.Key
	}

	// Build full crypto key resource ID for registration
	fullCryptoKeyID := fmt.Sprintf("%s/cryptoKeys/%s", keyConfig.KeyRing, keyConfig.CryptoKey)

	registerData := map[string]interface{}{
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

func (g *GCPKMSTest) Flags(fs *flag.FlagSet) {}
