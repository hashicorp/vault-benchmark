// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
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
	TestList[SSHKeySignTestType] = func() BenchmarkBuilder { return &SSHKeySignSecret{} }
}

type SSHKeySignSecret struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *SSHKeySignSecretConfig
	logger     hclog.Logger
	mountPath  string
}

type SSHKeySignSecretConfig struct {
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
	PublicKey       *string        `hcl:"public_key,optional"`
	TTL             string         `hcl:"ttl,optional"`
	ValidPrincipals string         `hcl:"valid_principals,optional"`
	CertType        string         `hcl:"cert_type,optional"`
	KeyID           string         `hcl:"key_id,optional"`
	CriticalOptions map[string]any `hcl:"critical_options,optional"`
	Extensions      map[string]any `hcl:"extensions,optional"`
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

	Name                   string            `hcl:"name,optional"`
	DefaultUser            string            `hcl:"default_user,optional"`
	DefaultUserTemplate    bool              `hcl:"default_user_template,optional"`
	CIDRList               []string          `hcl:"cidr_list,optional"`
	ExcludeCIDRList        []string          `hcl:"exclude_cidr_list,optional"`
	Port                   int               `hcl:"port,optional"`
	KeyType                string            `hcl:"key_type,optional"`
	AllowedUsers           []string          `hcl:"allowed_users,optional"`
	AllowedUsersTemplate   bool              `hcl:"allowed_users_template,optional"`
	AllowedDomains         []string          `hcl:"allowed_domains,optional"`
	TTL                    string            `hcl:"ttl,optional"`
	MaxTTL                 string            `hcl:"max_ttl,optional"`
	AllowedCriticalOptions []string          `hcl:"allowed_critical_options,optional"`
	AllowedExtensions      []string          `hcl:"allowed_extensions,optional"`
	DefaultCriticalOptions map[string]string `hcl:"default_critical_options,optional"`
	DefaultExtensions      map[string]string `hcl:"default_extensions,optional"`
	AllowUserCertificates  bool              `hcl:"allow_user_certificates,optional"`
	AllowHostCertificates  bool              `hcl:"allow_host_certificates,optional"`
	AllowBareDomains       bool              `hcl:"allow_bare_domains,optional"`
	AllowSubdomains        bool              `hcl:"allow_subdomains,optional"`
	AllowUserKeyIDs        bool              `hcl:"allow_user_key_ids,optional"`
	KeyIDFormat            string            `hcl:"key_id_format,optional"`
	AllowedUserKeyLengths  map[string]any    `hcl:"allowed_user_key_lengths,optional"`
	AlgorithmSigner        string            `hcl:"algorithm_signer,optional"`
	NotBeforeDuration      string            `hcl:"not_before_duration,optional"`
}

func (s *SSHKeySignSecret) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *SSHKeySignSecretConfig `hcl:"config,block"`
	}{
		Config: &SSHKeySignSecretConfig{
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

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	s.config = testConfig.Config
	return nil
}

func (s *SSHKeySignSecret) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	mountPath := mountName
	s.logger = targetLogger.Named(SSHKeySignTestType)

	mountPath, err = resolveMountPath(mountPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	s.logger.Trace(mountLogMessage("secrets", "ssh", mountPath))
	err = client.Sys().Mount(mountPath, &api.MountInput{
		Type: "ssh",
	})
	if err != nil {
		return nil, fmt.Errorf("error mounting ssh secrets engine: %v", err)
	}

	setupLogger := s.logger.Named(mountPath)

	setupLogger.Trace(parsingConfigLogMessage("ca"))
	if err := writeStruct(client, filepath.Join(mountPath, "config", "ca"), s.config.CAConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join(mountPath, "roles", s.config.RoleConfig.Name), s.config.RoleConfig); err != nil {
		return nil, err
	}

	if s.config.KeySigningConfig.PublicKey != nil {
		if ok, err := IsFile(*s.config.KeySigningConfig.PublicKey); ok {
			keyBytes, err := os.ReadFile(*s.config.KeySigningConfig.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("error parsing public key from file: %v", err)
			}
			keyString := string(keyBytes)
			s.config.KeySigningConfig.PublicKey = &keyString
		} else {
			if errors.Is(ErrIsDirectory, err) {
				return nil, fmt.Errorf("error parsing public key from file: %v", err)
			}
			setupLogger.Trace("parsing provided public key")
			_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*s.config.KeySigningConfig.PublicKey))
			if err != nil {
				return nil, fmt.Errorf("error parsing public key: %v", err)
			}
		}
	} else {
		setupLogger.Warn("public key not provided, generating test RSA key-pair")
		tKeyPair, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("error generating test RSA key-pair: %v", err)
		}

		pubKey, err := ssh.NewPublicKey(tKeyPair.Public())
		if err != nil {
			return nil, fmt.Errorf("error generating test RSA public key: %v", err)
		}

		pubKeyString := fmt.Sprintf("ssh-rsa %v", base64.StdEncoding.EncodeToString(pubKey.Marshal()))
		s.config.KeySigningConfig.PublicKey = &pubKeyString
	}

	// Sign Config
	setupLogger.Trace(parsingConfigLogMessage("key signing"))
	signingConfig, err := structToMap(s.config.KeySigningConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing key signing config from struct: %v", err)
	}

	signingConfigString, err := json.Marshal(signingConfig)
	if err != nil {
		return nil, fmt.Errorf("error marshalling key signing config data: %v", err)
	}

	return &SSHKeySignSecret{
		mountPath:  "/v1/" + mountPath,
		pathPrefix: "/v1/" + filepath.Join(mountPath, "sign", s.config.RoleConfig.Name),
		body:       []byte(signingConfigString),
		header:     generateHeader(client),
		logger:     s.logger,
	}, nil
}

func (s *SSHKeySignSecret) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: SSHKeySignTestMethod,
		URL:    client.Address() + s.pathPrefix,
		Body:   s.body,
		Header: s.header,
	}
}

func (s *SSHKeySignSecret) Cleanup(client *api.Client) error {
	return cleanupMount(s.logger, client, s.mountPath)
}

func (s *SSHKeySignSecret) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     SSHKeySignTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SSHKeySignSecret) Flags(fs *flag.FlagSet) {}
