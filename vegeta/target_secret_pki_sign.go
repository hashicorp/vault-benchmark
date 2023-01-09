package vegeta

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type pkiSignTest struct {
	pathPrefix string
	cn         string
	csr        string
	body       []byte
	header     http.Header
}

func (p *pkiSignTest) sign(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + p.pathPrefix,
		Body:   p.body,
		Header: p.header,
	}
}

type PkiSignTestConfig struct {
	SetupDelay  time.Duration
	RootKeyType string `json:"root_key_type"`
	RootKeyBits int    `json:"root_key_bits"`
	IntKeyType  string `json:"int_key_type"`
	IntKeyBits  int    `json:"int_key_bits"`
	LeafKeyType string `json:"leaf_key_type"`
	LeafKeyBits int    `json:"leaf_key_bits"`
	LeafStore   bool   `json:"leaf_store"`
	LeafLease   bool   `json:"leaf_lease"`
	LeafExpiry  string `json:"leaf_expiry"`
	CSRPath     string `json:"csr_path"`
	Key         string `json:"key"`
}

func (p *PkiSignTestConfig) FromJSON(path string) error {
	// Set defaults
	p.RootKeyType = "rsa"
	p.RootKeyBits = 2048
	p.IntKeyType = "rsa"
	p.IntKeyBits = 2048
	p.LeafKeyType = "rsa"
	p.LeafKeyBits = 2048
	p.LeafStore = false
	p.LeafLease = false
	p.LeafExpiry = ""

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(p); err != nil {
		return err
	}

	return nil
}

// generateCSR will generate a test CSR to use for PKI signing benchmarking
func GenerateCSR(config PkiSignTestConfig) (string, error) {
	cBundle := &certutil.CreationBundle{
		Params: &certutil.CreationParameters{
			Subject: pkix.Name{
				CommonName:         "test.server.dc1.consul",
				Country:            []string{"US"},
				Organization:       []string{"Hashicorp"},
				Locality:           []string{"San Francisco"},
				OrganizationalUnit: []string{"VaultBenchmarking"},
			},
			KeyType:  config.LeafKeyType,
			KeyBits:  config.LeafKeyBits,
			NotAfter: time.Now().Add(1 * time.Hour),
		},
	}
	csr, err := certutil.CreateCSR(cBundle, true)
	if err != nil {
		return "", err
	}

	bundle, err := csr.ToCSRBundle()
	if err != nil {
		return "", err
	}

	return bundle.CSR, nil
}

func setupPKISigning(client *api.Client, randomMounts bool, config PkiSignTestConfig) (*pkiSignTest, error) {
	pkiPathPrefix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	if !randomMounts {
		pkiPathPrefix = "pki"
	}

	err = createSigningRootCA(client, pkiPathPrefix, config)
	if err != nil {
		return nil, err
	}
	_, cn, err := createIntermediateSigningCA(client, pkiPathPrefix, config)
	if err != nil {
		return nil, err
	}

	var csr string

	if config.CSRPath != "" {
		// Load CSR file
		csrBytes, err := os.ReadFile(config.CSRPath)
		if err != nil {
			return nil, err
		}
		csr = string(csrBytes)
	} else {
		// Generate test CSR
		csr, err = GenerateCSR(config)
		if err != nil {
			return nil, err
		}
	}

	bodyData, err := json.Marshal(map[string]interface{}{
		"common_name": cn,
		"csr":         csr,
	})
	if err != nil {
		return nil, err
	}
	return &pkiSignTest{
		pathPrefix: "/v1/" + pkiPathPrefix + "-int/sign/consul-server",
		cn:         cn,
		csr:        csr,
		body:       bodyData,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

func createSigningRootCA(cli *api.Client, pfx string, config PkiSignTestConfig) error {
	rootPath := pfx + "-root"
	err := cli.Sys().Mount(rootPath, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return err
	}

	// Avoid slow mount setup:
	// URL: PUT $VAULT_ADDR/v1/9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal
	// Code: 404. Errors: * no handler for route "9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal". route entry not found.
	time.Sleep(config.SetupDelay)

	_, err = cli.Logical().Write(rootPath+"/root/generate/internal", map[string]interface{}{
		"common_name": "example.com",
		"ttl":         "87600h",
		"key_type":    config.RootKeyType,
		"key_bits":    config.RootKeyBits,
	})
	if err != nil {
		return err
	}

	_, err = cli.Logical().Write(rootPath+"/config/urls", map[string]interface{}{
		"issuing_certificates":   fmt.Sprintf("%s/v1/%s/ca", cli.Address(), rootPath),
		"crl_distribution_point": fmt.Sprintf("%s/v1/%s/crl", cli.Address(), rootPath),
	})
	return err
}

func createIntermediateSigningCA(cli *api.Client, pfx string, config PkiSignTestConfig) (string, string, error) {
	rootPath, intPath := pfx+"-root", pfx+"-int"

	err := cli.Sys().Mount(intPath, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return "", "", err
	}

	// Avoid slow mount setup:
	// URL: PUT $VAULT_ADDR/v1/9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal
	// Code: 404. Errors: * no handler for route "9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal". route entry not found.
	time.Sleep(config.SetupDelay)

	resp, err := cli.Logical().Write(intPath+"/intermediate/generate/internal", map[string]interface{}{
		"common_name": "example.com Intermediate Authority",
		"ttl":         "87600h",
		"key_type":    config.IntKeyType,
		"key_bits":    config.IntKeyBits,
	})
	if err != nil {
		return "", "", err
	}

	resp, err = cli.Logical().Write(rootPath+"/root/sign-intermediate", map[string]interface{}{
		"csr":    resp.Data["csr"].(string),
		"format": "pem_bundle",
		"ttl":    "43800h",
	})
	if err != nil {
		return "", "", err
	}

	_, err = cli.Logical().Write(intPath+"/intermediate/set-signed", map[string]interface{}{
		"certificate": strings.Join([]string{resp.Data["certificate"].(string), resp.Data["issuing_ca"].(string)}, "\n"),
	})
	if err != nil {
		return "", "", err
	}

	_, err = cli.Logical().Write(intPath+"/roles/consul-server", map[string]interface{}{
		"allowed_domains":  "server.dc1.consul",
		"allow_subdomains": "true",
		"allow_localhost":  "true",
		"allow_any_name":   "true",
		"allow_ip_sans":    "true",
		"ttl":              config.LeafExpiry,
		"max_ttl":          "720h",
		"generate_lease":   fmt.Sprintf("%t", config.LeafLease),
		"no_store":         fmt.Sprintf("%t", !config.LeafStore),
		"key_type":         config.LeafKeyType,
		"key_bits":         config.LeafKeyBits,
	})
	if err != nil {
		return "", "", err
	}

	return intPath + "/issue/consul-server", "server.dc1.consul", nil
}
