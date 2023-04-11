package benchmarktests

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

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
}

type TransitTestConfig struct {
	Config *TransitConfig `hcl:"config,block"`
}

type TransitConfig struct {
	PayloadLen           int                   `hcl:"payload_len,optional"`
	ContextLen           int                   `hcl:"context_len,optional"`
	TransitConfigKeys    *TransitConfigKeys    `hcl:"keys_config,block"`
	TransitConfigSign    *TransitConfigSign    `hcl:"sign_config,block"`
	TransitConfigVerify  *TransitConfigVerify  `hcl:"verify_config,block"`
	TransitConfigEncrypt *TransitConfigEncrypt `hcl:"encrypt_config,block"`
	TransitConfigDecrypt *TransitConfigDecrypt `hcl:"decrypt_config,block"`
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

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "transit",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting transit backend: %v", err)
	}

	// Generate Keys for testing
	keysConfigData, err := structToMap(config.TransitConfigKeys)
	if err != nil {
		return nil, fmt.Errorf("error decoding Transit Keys config from struct: %v", err)
	}

	_, err = client.Logical().Write(filepath.Join(secretPath, "keys", config.TransitConfigKeys.Name), keysConfigData)
	if err != nil {
		return nil, fmt.Errorf("error writing Transit Keys config: %v", err)
	}

	// Generate our payload and context
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
		signConfig := config.TransitConfigSign
		secretPath = filepath.Join(secretPath, "sign", signConfig.Name)
		return &TransitTest{
			pathPrefix: "/v1/" + secretPath,
			header:     generateHeader(client),
			body:       []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, signConfig.HashAlgorithm, base64Payload, signConfig.SignatureAlgorithm, signConfig.MarshalingAlgorithm)),
		}, nil

	case "verify":
		verifyConfig := config.TransitConfigVerify
		verifyData, err := structToMap(verifyConfig)
		if err != nil {
			return nil, fmt.Errorf("error decoding Transit Keys config from struct: %v", err)
		}
		verifyPath := filepath.Join(secretPath, "verify", verifyConfig.Name)

		// Sign the payload first
		resp, err := client.Logical().Write(filepath.Join(secretPath, "sign", verifyConfig.Name), verifyData)

		if err != nil {
			return nil, fmt.Errorf("error signing data: %v", err)
		}
		if resp == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign data: no response or invalid signature: %v", resp)
		}

		return &TransitTest{
			pathPrefix: "/v1/" + verifyPath,
			header:     generateHeader(client),
			body:       []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, verifyConfig.HashAlgorithm, base64Payload, resp.Data["signature"], verifyConfig.SignatureAlgorithm, verifyConfig.MarshalingAlgorithm)),
		}, nil
	case "encrypt":
		contextStr := ""

		if config.TransitConfigKeys.Derived {
			contextStr = fmt.Sprintf(`,"context":"%s"`, base64Context)
		}

		encryptConfig := config.TransitConfigEncrypt
		encryptPath := filepath.Join(secretPath, "encrypt", encryptConfig.Name)

		return &TransitTest{
			pathPrefix: "/v1/" + encryptPath,
			header:     generateHeader(client),
			body:       []byte(fmt.Sprintf(`{"plaintext":"%s"%s}`, base64Payload, contextStr)),
		}, nil
	case "decrypt":
		data := map[string]interface{}{
			"plaintext": base64Payload,
		}
		contextStr := ""
		if config.TransitConfigKeys.Derived {
			data["context"] = base64Context
			contextStr = fmt.Sprintf(`,"context":"%s"`, base64Context)
		}

		// Encrypt the payload first
		decryptConfig := config.TransitConfigDecrypt
		decryptPath := filepath.Join(secretPath, "decrypt", decryptConfig.Name)

		resp, err := client.Logical().Write(filepath.Join(secretPath, "encrypt", decryptConfig.Name), data)
		if err != nil {
			return nil, fmt.Errorf("error encrypting data: %v", err)
		}
		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt data: no response or invalid ciphertext: %v", resp)
		}

		// Now decrypt it
		return &TransitTest{
			pathPrefix: "/v1/" + decryptPath,
			header:     generateHeader(client),
			body:       []byte(fmt.Sprintf(`{"ciphertext":"%s"%s}`, resp.Data["ciphertext"], contextStr)),
		}, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported transit operation: %v", t.action)
	}
}

func (t *TransitTest) Flags(fs *flag.FlagSet) {}
