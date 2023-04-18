package benchmarktests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	mountPath  string
	pathPrefix string
	body       []byte
	header     http.Header
	config     *SSHKeySignConfig
	logger     hclog.Logger
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
	GenerateSigningKey *bool  `hcl:"generate_signing_key,optional"`
	KeyType            string `hcl:"key_type,optional"`
	KeyBits            int    `hcl:"key_bits,optional"`
}

type SSHKeySigningConfig struct {
	PublicKey       *string                `hcl:"public_key,optional"`
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
	s.logger.Trace("unmounting", "path", hclog.Fmt("%v", s.mountPath))
	_, err := client.Logical().Delete(strings.Replace(s.mountPath, "/v1/", "/sys/mounts/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (s *SSHKeySignTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     SSHKeySignTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SSHKeySignTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	config := s.config.Config
	s.logger = targetLogger.Named(SSHKeySignTestType)

	if randomMountName {
		mountPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create SSH Secrets engine Mount
	s.logger.Trace("mounting ssh secrets engine at", "path", hclog.Fmt("%v", mountPath))
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "ssh",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting ssh secrets engine: %v", err)
	}

	setupLogger := s.logger.Named(mountPath)

	// Decode CA Config into mapstructure to pass with request
	setupLogger.Trace("decoding ca config data")
	caConfig, err := structToMap(config.CAConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding ca config from struct: %v", err)
	}

	// Write CA Config
	setupLogger.Trace("writing ca config")
	caPath := filepath.Join(mountPath, "config", "ca")
	_, err = client.Logical().Write(caPath, caConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing ca config: %v", err)
	}

	// Decode Role Config into mapstructure to pass with request
	setupLogger.Trace("decoding role config data")
	roleConfig, err := structToMap(config.RoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}

	// Write Role
	setupLogger.Trace("writing role", "name", hclog.Fmt("%v", config.RoleConfig.Name))
	rolePath := filepath.Join(mountPath, "roles", config.RoleConfig.Name)
	_, err = client.Logical().Write(rolePath, roleConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing role: %v", err)
	}

	// Check to see if a public key was provided already
	if config.KeySigningConfig.PublicKey != nil {
		// Check to see if we got a file or a string and handle
		if ok, err := IsFile(*config.KeySigningConfig.PublicKey); ok {
			keyBytes, err := os.ReadFile(*config.KeySigningConfig.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("error parsing public key from file: %v", err)
			}
			keyString := string(keyBytes)
			config.KeySigningConfig.PublicKey = &keyString
		} else {
			if errors.Is(IsDirectoryErr, err) {
				return nil, fmt.Errorf("error parsing public key from file: %v", err)
			}
			setupLogger.Trace("parsing provided public key")
			// Attempt to parse public key to verify its in a valid format
			_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*config.KeySigningConfig.PublicKey))
			if err != nil {
				return nil, fmt.Errorf("error parsing public key: %v", err)
			}
		}
	} else {
		// Create test key-pair
		setupLogger.Trace("generating test RSA key-pair")
		tKeyPair, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("error generating test RSA key-pair: %v", err)
		}

		// Get Public key to sign
		pubKey, err := ssh.NewPublicKey(tKeyPair.Public())
		if err != nil {
			return nil, fmt.Errorf("error generating test RSA public key: %v", err)
		}

		pubKeyString := fmt.Sprintf("ssh-rsa %v", base64.StdEncoding.EncodeToString(pubKey.Marshal()))
		config.KeySigningConfig.PublicKey = &pubKeyString
	}

	// Sign Config
	setupLogger.Trace("decoding key signing config data")
	signingConfig, err := structToMap(config.KeySigningConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding key signing config from struct: %v", err)
	}

	signingConfigString, err := json.Marshal(signingConfig)
	if err != nil {
		return nil, fmt.Errorf("error marshalling key signing config data: %v", err)
	}

	return &SSHKeySignTest{
		mountPath:  "/v1/" + mountPath,
		pathPrefix: "/v1/" + filepath.Join(mountPath, "sign", config.RoleConfig.Name),
		body:       []byte(signingConfigString),
		header:     generateHeader(client),
		logger:     s.logger,
	}, nil
}

func (s *SSHKeySignTest) Flags(fs *flag.FlagSet) {}
