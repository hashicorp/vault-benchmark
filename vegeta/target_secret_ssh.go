package vegeta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type sshTest struct {
	pathPrefix string
	keyType    string
	keyBits    int
	header     http.Header
}

func (s *sshTest) write(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + s.pathPrefix,
		Body:   []byte(fmt.Sprintf(`{"key_type": "%s", "key_bits": "%d"}`, s.keyType, s.keyBits)),
		Header: s.header,
	}
}

func setupSSH(client *api.Client, randomMounts bool, config SshCaTestConfig) (*sshTest, error) {
	sshPathPrefix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	sshPathPrefix += "-ssh"
	if !randomMounts {
		sshPathPrefix = "ssh"
	}

	err = client.Sys().Mount(sshPathPrefix, &api.MountInput{
		Type: "ssh",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return nil, err
	}

	_, err = client.Logical().Write(sshPathPrefix+"/config/ca", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "87600h",
		"key_type":    config.CAKeyType,
		"key_bits":    config.CAKeyBits,
	})
	if err != nil {
		return nil, err
	}

	_, err = client.Logical().Write(sshPathPrefix+"/roles/consul-server", map[string]interface{}{
		"key_type":                "ca",
		"allow_user_certificates": "true",
	})
	if err != nil {
		return nil, err
	}

	return &sshTest{
		pathPrefix: "/v1/" + sshPathPrefix + "/issue/consul-server",
		keyType:    config.LeafKeyType,
		keyBits:    config.LeafKeyBits,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

type SshCaTestConfig struct {
	SetupDelay  time.Duration
	CAKeyType   string `json:"ca_key_type"`
	CAKeyBits   int    `json:"ca_key_bits"`
	LeafKeyType string `json:"leaf_key_type"`
	LeafKeyBits int    `json:"leaf_key_bits"`
}

func (s *SshCaTestConfig) FromJSON(path string) error {
	// Set defaults
	s.CAKeyType = "rsa"
	s.CAKeyBits = 2048
	s.LeafKeyType = "rsa"
	s.LeafKeyBits = 2048

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(s); err != nil {
		return err
	}

	return nil
}
