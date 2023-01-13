package vegeta

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type transitTest struct {
	pathPrefix string
	body       []byte
	header     http.Header
}

func (t *transitTest) write(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + t.pathPrefix,
		Body:   t.body,
		Header: t.header,
	}
}

func (t *transitTest) cleanup(client *api.Client) error {
	re := regexp.MustCompile(`(?m)/v1/(\S+)/\S+/\S+`)
	_, err := client.Logical().Delete(re.ReplaceAllString(t.pathPrefix, "/sys/mounts/$1"))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

type transitTestConfig struct {
	SetupDelay          time.Duration
	Derived             bool   `json:"derived"`
	Convergent          bool   `json:"convergent"`
	KeyType             string `json:"key_type"`
	PayloadLen          int    `json:"payload_len"`
	ContextLen          int    `json:"context_len"`
	Hash                string `json:"hash_algorithm"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	MarshalingAlgorithm string `json:"marshaling_algorithm"`
}

func (t *transitTestConfig) FromJSON(path string) error {
	// Set defaults
	t.Derived = false
	t.Convergent = false
	t.KeyType = "rsa-2048"
	t.PayloadLen = 2048
	t.ContextLen = 32
	t.Hash = "sha2-256"
	t.SignatureAlgorithm = "pss"
	t.MarshalingAlgorithm = "asn1"

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(t); err != nil {
		return err
	}

	return nil
}

func setupTransit(client *api.Client, randomMounts bool, operation string, config transitTestConfig) (*transitTest, error) {
	pathPrefix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	pathPrefix += "-transit-" + operation
	if !randomMounts {
		pathPrefix = "transit-" + operation
	}

	err = client.Sys().Mount(pathPrefix, &api.MountInput{
		Type: "transit",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, err
	}

	// Generate keys if it isn't the subject of our benchmark.
	if operation != "generate" {
		_, err = client.Logical().Write(pathPrefix+"/keys/testing", map[string]interface{}{
			"derived":               config.Derived,
			"convergent_encryption": config.Convergent,
			"type":                  config.KeyType,
		})
		if err != nil {
			return nil, err
		}
	}

	ret := &transitTest{
		pathPrefix: "/v1/" + pathPrefix,
		body:       []byte(""),
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
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
	switch operation {
	case "sign":
		ret.pathPrefix += "/sign/testing"
		ret.body = []byte(fmt.Sprintf(`{"hash_algorithm":"%s","input":"%s","signature_algorithm":"%s","marshaling_algorithm":"%s"}`, config.Hash, base64Payload, config.SignatureAlgorithm, config.MarshalingAlgorithm))
	case "verify":
		resp, err := client.Logical().Write(pathPrefix+"/sign/testing", map[string]interface{}{
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

		resp, err := client.Logical().Write(pathPrefix+"/encrypt/testing", data)
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
		return nil, fmt.Errorf("unknown or unsupported transit operation: %v", operation)
	}

	return ret, nil
}
