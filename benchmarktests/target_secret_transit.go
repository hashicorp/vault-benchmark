package benchmarktests

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"

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
	Derived             bool   `hcl:"derived,optional"`
	Convergent          bool   `hcl:"convergent_encryption,optional"`
	KeyType             string `hcl:"type,optional"`
	PayloadLen          int    `hcl:"payload_len,optional"`
	ContextLen          int    `hcl:"context_len,optional"`
	Hash                string `hcl:"hash_algorithm,optional"`
	SignatureAlgorithm  string `hcl:"signature_algorithm,optional"`
	MarshalingAlgorithm string `hcl:"marshaling_algorithm,optional"`
}

func (t *TransitTest) ParseConfig(body hcl.Body) error {
	t.config = &TransitTestConfig{
		Config: &TransitConfig{
			Derived:             false,
			Convergent:          false,
			KeyType:             "rsa-2048",
			PayloadLen:          128,
			ContextLen:          32,
			Hash:                "sha2-256",
			SignatureAlgorithm:  "pss",
			MarshalingAlgorithm: "asn1",
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
	re := regexp.MustCompile(`(?m)/v1/(\S+)/\S+/\S+`)
	_, err := client.Logical().Delete(re.ReplaceAllString(t.pathPrefix, "/sys/mounts/$1"))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (t *TransitTest) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     TransitSecretTestMethod,
		pathPrefix: t.pathPrefix,
	}
	return tInfo
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
	secretPath += "-transit-" + t.action

	err = client.Sys().Mount(secretPath, &api.MountInput{
		Type: "transit",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, err
	}

	// Generate keys if it isn't the subject of our benchmark.
	if t.action != "generate" {
		_, err = client.Logical().Write(secretPath+"/keys/testing", map[string]interface{}{
			"derived":               config.Derived,
			"convergent_encryption": config.Convergent,
			"type":                  config.KeyType,
		})
		if err != nil {
			return nil, err
		}
	}

	ret := &TransitTest{
		pathPrefix: "/v1/" + secretPath,
		body:       []byte(""),
		header:     generateHeader(client),
	}

	// Generate our payload and context
	rawPayload, err := uuid.GenerateRandomBytes(config.PayloadLen)
	if err != nil {
		return nil, err
	}
	base64Payload := base64.StdEncoding.EncodeToString(rawPayload)

	rawContext, err := uuid.GenerateRandomBytes(config.ContextLen)
	if err != nil {
		return nil, err
	}
	base64Context := base64.StdEncoding.EncodeToString(rawContext)

	// Now dispatch the operation.
	switch t.action {
	case "sign":
		ret.pathPrefix += "/sign/testing"
		ret.body = []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, config.Hash, base64Payload, config.SignatureAlgorithm, config.MarshalingAlgorithm))
	case "verify":
		resp, err := client.Logical().Write(secretPath+"/sign/testing", map[string]interface{}{
			"hash_algorithm":       config.Hash,
			"input":                base64Payload,
			"signature_algorithm":  config.SignatureAlgorithm,
			"marshaling_algorithm": config.MarshalingAlgorithm,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || len(resp.Data["signature"].(string)) == 0 {
			return nil, fmt.Errorf("unable to sign data: no response or invalid signature: %v", resp)
		}

		ret.pathPrefix += "/verify/testing"
		ret.body = []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, config.Hash, base64Payload, resp.Data["signature"], config.SignatureAlgorithm, config.MarshalingAlgorithm))
	case "encrypt":
		ret.pathPrefix += "/encrypt/testing"

		contextStr := ""
		if config.Derived {
			contextStr = fmt.Sprintf(`,"context":"%s"`, base64Context)
		}

		ret.body = []byte(fmt.Sprintf(`{"plaintext":"%s"%s}`, base64Payload, contextStr))
	case "decrypt":
		data := map[string]interface{}{
			"plaintext": base64Payload,
		}
		if config.Derived {
			data["context"] = base64Context
		}

		resp, err := client.Logical().Write(secretPath+"/encrypt/testing", data)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Data["ciphertext"] == nil || len(resp.Data["ciphertext"].(string)) == 0 {
			return nil, fmt.Errorf("unable to encrypt data: no response or invalid ciphertext: %v", resp)
		}

		contextStr := ""
		if config.Derived {
			contextStr = fmt.Sprintf(`,"context":"%s"`, base64Context)
		}

		ret.pathPrefix += "/decrypt/testing"
		ret.body = []byte(fmt.Sprintf(`{"ciphertext":"%s"%s}`, resp.Data["ciphertext"], contextStr))
	default:
		return nil, fmt.Errorf("unknown or unsupported transit operation: %v", t.action)
	}

	return ret, nil
}

func (t *TransitTest) Flags(fs *flag.FlagSet) {}
