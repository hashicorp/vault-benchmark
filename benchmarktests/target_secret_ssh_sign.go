package benchmarktests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
	"golang.org/x/crypto/ssh"
)

const (
	SSHKeySignTestType   = "ssh_sign"
	SSHKeySignTestMethod = "POST"
)

func init() {
	TestList[SSHKeySignTestType] = func() BenchmarkBuilder { return &SSHKeySignTest{} }
}

type SSHKeySignTest struct {
	pathPrefix string
	body       []byte
	header     http.Header
	config     *SSHKeySignConfig
}

type SSHKeySignConfig struct {
	Config *SSHKeySignTestConfig `hcl:"config,block"`
}

type SSHKeySignTestConfig struct {
	CAConfig         *SSHKeySignCAConfig   `hcl:"ca,block"`
	RoleConfig       *SSHKeySignRoleConfig `hcl:"role,block"`
	KeySigningConfig *SSHKeySigningConfig  `hcl:"key_signing,block"`
}

type SSHKeySignCAConfig struct {
	PrivateKey         string `hcl:"private_key,optional"`
	PublicKey          string `hcl:"public_key,optional"`
	GenerateSigningKey bool   `hcl:"generate_signing_key,optional"`
	KeyType            string `hcl:"key_type,optional"`
	KeyBits            int    `hcl:"key_bits,optional"`
}

type SSHKeySigningConfig struct {
	PublicKey       string                 `hcl:"public_key,optional"`
	TTL             string                 `hcl:"ttl,optional"`
	ValidPrincipals string                 `hcl:"valid_principals,optional"`
	CertType        string                 `hcl:"cert_type,optional"`
	KeyID           string                 `hcl:"key_id,optional"`
	CriticalOptions map[string]interface{} `hcl:"critical_options,optional"`
	Extensions      map[string]interface{} `hcl:"extensions,optional"`
}

type SSHKeySignRoleConfig struct {
	// Vault >= 1.13.x
	AllowedDomainsTemplate bool `hcl:"allowed_domains_template,optional"`

	// Vault <= 1.12.x
	Key            string   `hcl:"key,optional"`
	AdminUser      string   `hcl:"admin_user,optional"`
	KeyBits        int      `hcl:"key_bits,optional"`
	InstallScript  string   `hcl:"install_script,optional"`
	KeyOptionSpecs []string `hcl:"key_option_specs,optional"`

	// Common
	Name                   string                 `hcl:"name,optional"`
	DefaultUser            string                 `hcl:"default_user,optional"`
	DefaultUserTemplate    bool                   `hcl:"default_user_template,optional"`
	CIDRList               []string               `hcl:"cidr_list,optional"`
	ExcludeCIDRList        []string               `hcl:"exclude_cidr_list,optional"`
	Port                   int                    `hcl:"port,optional"`
	KeyType                string                 `hcl:"key_type,optional"`
	AllowedUsers           []string               `hcl:"allowed_users,optional"`
	AllowedUsersTemplate   bool                   `hcl:"allowed_users_template,optional"`
	AllowedDomains         []string               `hcl:"allowed_domains,optional"`
	TTL                    string                 `hcl:"ttl,optional"`
	MaxTTL                 string                 `hcl:"max_ttl,optional"`
	AllowedCriticalOptions []string               `hcl:"allowed_critical_options,optional"`
	AllowedExtensions      []string               `hcl:"allowed_extensions,optional"`
	DefaultCriticalOptions map[string]string      `hcl:"default_critical_options,optional"`
	DefaultExtensions      map[string]string      `hcl:"default_extensions,optional"`
	AllowUserCertificates  bool                   `hcl:"allow_user_certificates,optional"`
	AllowHostCertificates  bool                   `hcl:"allow_host_certificates,optional"`
	AllowBareDomains       bool                   `hcl:"allow_bare_domains,optional"`
	AllowSubdomains        bool                   `hcl:"allow_subdomains,optional"`
	AllowUserKeyIDs        bool                   `hcl:"allow_user_key_ids,optional"`
	KeyIDFormat            string                 `hcl:"key_id_format,optional"`
	AllowedUserKeyLengths  map[string]interface{} `hcl:"allowed_user_key_lengths,optional"`
	AlgorithmSigner        string                 `hcl:"algorithm_signer,optional"`
	NotBeforeDuration      string                 `hcl:"not_before_duration,optional"`
}

func (s *SSHKeySignTest) ParseConfig(body hcl.Body) error {
	s.config = &SSHKeySignConfig{
		Config: &SSHKeySignTestConfig{
			CAConfig: &SSHKeySignCAConfig{
				KeyType: "rsa",
				KeyBits: 0,
			},
			RoleConfig: &SSHKeySignRoleConfig{
				Name:                  "benchmark-role",
				KeyType:               "ca",
				AllowUserCertificates: true,
			},
			KeySigningConfig: &SSHKeySigningConfig{
				CertType: "user",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, s.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (s *SSHKeySignTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: SSHKeySignTestMethod,
		URL:    client.Address() + s.pathPrefix,
		Body:   s.body,
		Header: s.header,
	}
}

func (s *SSHKeySignTest) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(s.pathPrefix, "/v1/", "/sys/", 1))

	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *SSHKeySignTest) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     SSHKeySignTestMethod,
		pathPrefix: s.pathPrefix,
	}
	return tInfo
}

func (s *SSHKeySignTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	config := s.config.Config

	if randomMountName {
		mountPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create SSH Secrets engine Mount
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "ssh",
	})
	if err != nil {
		return nil, err
	}

	// Decode CA Config into mapstructure to pass with request
	caConfig, err := structToMap(config.CAConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding ca config from struct: %v", err)
	}

	// Write CA Config
	caPath := filepath.Join(mountPath, "config", "ca")
	_, err = client.Logical().Write(caPath, caConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing ca config: %v", err)
	}

	// Decode Role Config into mapstructure to pass with request
	roleConfig, err := structToMap(config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}

	// Write Role
	rolePath := filepath.Join(mountPath, "roles", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing role: %v", err)
	}

	// Create test key-pair
	tKeyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("error generating test RSA key-pair: %v", err)
	}

	// Get Public key to sign
	pubKey, err := ssh.NewPublicKey(tKeyPair.Public())
	if err != nil {
		return nil, fmt.Errorf("error generating test RSA public key: %v", err)
	}

	config.KeySigningConfig.PublicKey = "ssh-rsa " + base64.StdEncoding.EncodeToString(pubKey.Marshal())

	// Sign Config
	signingConfig, err := structToMap(config.KeySigningConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding key signing config from struct: %v", err)
	}

	signingConfigString, err := json.Marshal(signingConfig)
	if err != nil {
		return nil, fmt.Errorf("error marshalling key signing config data: %v", err)
	}

	return &SSHKeySignTest{
		pathPrefix: "/v1/" + filepath.Join(mountPath, "sign", config.RoleConfig.Name),
		body:       []byte(signingConfigString),
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

func (s *SSHKeySignTest) Flags(fs *flag.FlagSet) {}
