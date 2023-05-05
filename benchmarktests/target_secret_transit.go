package benchmarktests

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
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
	TransitSignSecretTestType    = "transit_sign"
	TransitVerifySecretTestType  = "transit_verify"
	TransitEncryptSecretTestType = "transit_encrypt"
	TransitDecryptSecretTestType = "transit_decrypt"
	TransitSecretTestMethod      = "POST"
)

func init() {
	// "Register" this test to the main test registry
	TestList[TransitSignSecretTestType] = func() BenchmarkBuilder { return &TransitTest{action: "sign"} }
	TestList[TransitVerifySecretTestType] = func() BenchmarkBuilder { return &TransitTest{action: "verify"} }
	TestList[TransitEncryptSecretTestType] = func() BenchmarkBuilder { return &TransitTest{action: "encrypt"} }
	TestList[TransitDecryptSecretTestType] = func() BenchmarkBuilder { return &TransitTest{action: "decrypt"} }
}

type TransitTest struct {
	action     string
	pathPrefix string
	body       []byte
	header     http.Header
	config     *TransitTestConfig
	logger     hclog.Logger
}

type TransitTestConfig struct {
	Config *TransitConfig `hcl:"config,block"`
}

type TransitConfig struct {
	PayloadLen           int                   `hcl:"payload_len,optional"`
	ContextLen           int                   `hcl:"context_len,optional"`
	TransitConfigKeys    *TransitConfigKeys    `hcl:"keys,block"`
	TransitConfigSign    *TransitConfigSign    `hcl:"sign,block"`
	TransitConfigVerify  *TransitConfigVerify  `hcl:"verify,block"`
	TransitConfigEncrypt *TransitConfigEncrypt `hcl:"encrypt,block"`
	TransitConfigDecrypt *TransitConfigDecrypt `hcl:"decrypt,block"`
}

// /transit/keys/:name
type TransitConfigKeys struct {
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
}

// /transit/sign/:name
type TransitConfigSign struct {
	Name                string        `hcl:"name,optional"`
	KeyVersion          int           `hcl:"key_version,optional"`
	HashAlgorithm       string        `hcl:"hash_algorithm,optional"`
	Input               string        `hcl:"input,optional"`
	Reference           string        `hcl:"reference,optional"`
	BatchInput          []interface{} `hcl:"batch_input,optional"`
	Context             string        `hcl:"context,optional"`
	Prehashed           bool          `hcl:"prehashed,optional"`
	SignatureAlgorithm  string        `hcl:"signature_algorithm,optional"`
	MarshalingAlgorithm string        `hcl:"marshaling_algorithm,optional"`
	SaltLength          string        `hcl:"salt_length,optional"`
}

// /transit/verify/:name(/:hash_algorithm)
type TransitConfigVerify struct {
	Name                string        `hcl:"name,optional"`
	HashAlgorithm       string        `hcl:"hash_algorithm,optional"`
	Input               string        `hcl:"input,optional"`
	Signature           string        `hcl:"signature,optional"`
	HMAC                string        `hcl:"hmac,optional"`
	Reference           string        `hcl:"reference,optional"`
	BatchInput          []interface{} `hcl:"batch_input,optional"`
	Context             string        `hcl:"context,optional"`
	Prehashed           bool          `hcl:"prehashed,optional"`
	SignatureAlgorithm  string        `hcl:"signature_algorithm,optional"`
	MarshalingAlgorithm string        `hcl:"marshaling_algorithm,optional"`
	SaltLength          string        `hcl:"salt_length,optional"`
}

// /transit/encrypt/:name
type TransitConfigEncrypt struct {
	Name                       string        `hcl:"name,optional"`
	Plaintext                  string        `hcl:"plaintext,optional"`
	AssociatedData             string        `hcl:"associated_data,optional"`
	Context                    string        `hcl:"context,optional"`
	KeyVersion                 int           `hcl:"key_version,optional"`
	Nonce                      string        `hcl:"nonce,optional"`
	Reference                  string        `hcl:"reference,optional"`
	BatchInput                 []interface{} `hcl:"batch_input,optional"`
	Type                       string        `hcl:"type,optional"`
	ConvergentEncryption       bool          `hcl:"convergent_encryption,optional"`
	PartialFailureResponseCode int           `hcl:"partial_failure_response_code,optional"`
}

// /transit/decrypt/:name
type TransitConfigDecrypt struct {
	Name                       string        `hcl:"name,optional"`
	Ciphertext                 string        `hcl:"ciphertext,optional"`
	AssociatedData             string        `hcl:"associated_data,optional"`
	Context                    string        `hcl:"context,optional"`
	Nonce                      string        `hcl:"nonce,optional"`
	Reference                  string        `hcl:"reference,optional"`
	BatchInput                 []interface{} `hcl:"batch_input,optional"`
	PartialFailureResponseCode int           `hcl:"partial_failure_response_code,optional"`
}

func (t *TransitTest) ParseConfig(body hcl.Body) error {
	t.config = &TransitTestConfig{
		Config: &TransitConfig{
			TransitConfigKeys: &TransitConfigKeys{
				Name:                 "test",
				ConvergentEncryption: false,
				Derived:              false,
				Type:                 "rsa-2048",
			},
			TransitConfigSign: &TransitConfigSign{
				Name:                "test",
				HashAlgorithm:       "sha2-256",
				SignatureAlgorithm:  "pss",
				MarshalingAlgorithm: "asn1",
			},
			TransitConfigVerify: &TransitConfigVerify{
				Name:                "test",
				HashAlgorithm:       "sha2-256",
				SignatureAlgorithm:  "pss",
				MarshalingAlgorithm: "asn1",
			},
			TransitConfigEncrypt: &TransitConfigEncrypt{
				Name: "test",
			},
			TransitConfigDecrypt: &TransitConfigDecrypt{
				Name: "test",
			},
			PayloadLen: 128,
			ContextLen: 32,
		},
	}

	diags := gohcl.DecodeBody(body, nil, t.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	return nil
}

func (t *TransitTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: TransitSecretTestMethod,
		URL:    client.Address() + t.pathPrefix,
		Body:   t.body,
		Header: t.header,
	}
}

func (t *TransitTest) Cleanup(client *api.Client) error {
	parts := strings.Split(t.pathPrefix, "/")
	t.logger.Trace(cleanupLogMessage(parts[2]))
	_, err := client.Logical().Delete(fmt.Sprintf("/sys/mounts/%s", parts[2]))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TransitTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     TransitSecretTestMethod,
		pathPrefix: t.pathPrefix,
	}
}
func (t *TransitTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := t.config.Config
	switch t.action {
	case "sign":
		t.logger = targetLogger.Named(TransitSignSecretTestType)
	case "verify":
		t.logger = targetLogger.Named(TransitVerifySecretTestType)
	case "encrypt":
		t.logger = targetLogger.Named(TransitEncryptSecretTestType)
	case "decrypt":
		t.logger = targetLogger.Named(TransitDecryptSecretTestType)
	}

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
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
	// Generate Keys for testing
	setupLogger.Trace(parsingConfigLogMessage("transit key"))
	keysConfigData, err := structToMap(config.TransitConfigKeys)
	if err != nil {
		return nil, fmt.Errorf("error parsing transit key config from struct: %v", err)
	}

	setupLogger.Trace(writingLogMessage("key config"), "name", config.TransitConfigKeys.Name)
	_, err = client.Logical().Write(filepath.Join(secretPath, "keys", config.TransitConfigKeys.Name), keysConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing transit key config: %v", err)
	}

	// Generate our payload and context
	setupLogger.Trace("generating test payload and context")
	rawPayload, err := uuid.GenerateRandomBytes(config.PayloadLen)
	if err != nil {
		return nil, fmt.Errorf("error generating random payload: %v", err)
	}
	base64Payload := base64.StdEncoding.EncodeToString(rawPayload)

	rawContext, err := uuid.GenerateRandomBytes(config.ContextLen)
	if err != nil {
		return nil, fmt.Errorf("error generating random context: %v", err)
	}
	base64Context := base64.StdEncoding.EncodeToString(rawContext)

	// Now dispatch the operation.
	switch t.action {
	case "sign":
		secretPath = filepath.Join(secretPath, "sign", config.TransitConfigSign.Name)
		setupLogger.Trace(parsingConfigLogMessage("sign"))
		signConfigData, err := structToMap(config.TransitConfigSign)
		if err != nil {
			return nil, fmt.Errorf("error parsing sign config from struct: %v", err)
		}

		signingDataString, err := json.Marshal(signConfigData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling signing config data: %v", err)
		}

		return &TransitTest{
			pathPrefix: "/v1/" + secretPath,
			header:     generateHeader(client),
			body:       []byte(signingDataString),
			logger:     t.logger,
		}, nil

	case "verify":
		setupLogger.Trace(parsingConfigLogMessage("transit verify"))
		signData, err := structToMap(config.TransitConfigVerify)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit verify config from struct: %v", err)
		}
		verifyPath := filepath.Join(secretPath, "verify", config.TransitConfigVerify.Name)

		// Sign the payload first
		setupLogger.Trace("signing payload")
		resp, err := client.Logical().Write(filepath.Join(secretPath, "sign", config.TransitConfigVerify.Name), signData)
		if err != nil {
			return nil, fmt.Errorf("error signing payload: %v", err)
		}

		if resp == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign payload: no response or invalid signature: %v", resp)
		}
		config.TransitConfigVerify.Signature = resp.Data["signature"].(string)

		setupLogger.Trace(parsingConfigLogMessage("transit verify"))
		verifyData, err := structToMap(config.TransitConfigVerify)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit verify config from struct: %v", err)
		}

		verifyDataString, err := json.Marshal(verifyData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling transit verify data: %v", err)
		}

		return &TransitTest{
			pathPrefix: "/v1/" + verifyPath,
			header:     generateHeader(client),
			body:       []byte(verifyDataString),
			logger:     t.logger,
		}, nil

	case "encrypt":
		if config.TransitConfigKeys.Derived {
			config.TransitConfigEncrypt.Context = base64Context
		}
		config.TransitConfigEncrypt.Plaintext = base64Payload

		setupLogger.Trace(parsingConfigLogMessage("transit encrypt"))
		encryptData, err := structToMap(config.TransitConfigEncrypt)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit encrypt config from struct: %v", err)
		}

		encryptDataString, err := json.Marshal(encryptData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling transit encrypt data: %v", err)
		}

		encryptPath := filepath.Join(secretPath, "encrypt", config.TransitConfigEncrypt.Name)
		return &TransitTest{
			pathPrefix: "/v1/" + encryptPath,
			header:     generateHeader(client),
			body:       []byte(encryptDataString),
			logger:     t.logger,
		}, nil

	case "decrypt":
		// Encrypt test payload
		testEncryptData := map[string]interface{}{
			"plaintext": base64Payload,
		}

		if config.TransitConfigKeys.Derived {
			config.TransitConfigDecrypt.Context = base64Context
			testEncryptData["context"] = base64Context
		}

		setupLogger.Trace("encrypting payload")
		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", config.TransitConfigDecrypt.Name), testEncryptData)
		if err != nil {
			return nil, fmt.Errorf("error encrypting payload: %v", err)
		}

		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt payload: no response or invalid ciphertext: %v", resp)
		}

		config.TransitConfigDecrypt.Ciphertext = resp.Data["ciphertext"].(string)

		// Prepare for decryption
		decryptPath := filepath.Join(secretPath, "decrypt", config.TransitConfigDecrypt.Name)

		setupLogger.Trace(parsingConfigLogMessage("transit decrypt"))
		decryptData, err := structToMap(config.TransitConfigDecrypt)
		if err != nil {
			return nil, fmt.Errorf("error parsing transit decrypt config: %v", err)
		}

		decryptDataString, err := json.Marshal(decryptData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling transit decrypt data: %v", err)
		}

		// Now decrypt it
		return &TransitTest{
			pathPrefix: "/v1/" + decryptPath,
			header:     generateHeader(client),
			body:       []byte(decryptDataString),
			logger:     t.logger,
		}, nil

	default:
		return nil, fmt.Errorf("unknown or unsupported transit operation: %v", t.action)
	}
}

func (t *TransitTest) Flags(fs *flag.FlagSet) {}
