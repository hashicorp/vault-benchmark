package vegeta

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
	"golang.org/x/crypto/ssh"
)

/*
/ssh/sign/:role_name
*/

type sshSigntest struct {
	pathPrefix   string
	role         string
	publicKeyRSA string
	header       http.Header
}

type SSHSignerCAConfig struct {
	PrivateKey         string
	PublicKey          string
	GenerateSigningKey bool
	KeyType            string
	KeyBits            int
}

type SSHSignerRoleConfig struct {
	Name                   string
	Key                    string
	AdminUser              string
	DefaultUser            string
	DefaultUserTemplate    bool
	CIDRList               []string
	ExcludeCIDRList        []string
	Port                   int
	KeyType                string
	KeyBits                int
	InstallScript          string
	AllowedUsers           []string
	AllowedUsersTemplate   bool
	AllowedDomains         []string
	KeyOptionSpecs         []string
	TTL                    string
	MaxTTL                 string
	AllowedCriticalOptions []string
	AllowedExtensions      []string
	DefaultCriticalOptions map[string]string
	DefaultExtensions      map[string]string
	AllowUserCertificates  bool
	AllowHostCertificates  bool
	AllowBareDomains       bool
	AllowSubdomains        bool
	AllowUserKeyIDs        bool
	KeyIDFormat            string
	AllowedUserKeyLengths  map[string]interface{}
	AlgorithmSigner        string
	NotBeforeDuration      string
}

func (c *SSHSignerCAConfig) FromJSON(path string) error {
	c.GenerateSigningKey = true
	c.KeyType = "ssh-rsa"
	c.KeyBits = 0

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(c); err != nil {
		return err
	}
	return nil
}

func (r *SSHSignerRoleConfig) FromJSON(path string) error {
	r.Port = 22
	r.KeyBits = 1024
	r.AlgorithmSigner = "default"
	r.NotBeforeDuration = "30s"
	r.KeyType = "ca"
	r.AllowUserCertificates = true

	if path == "" {
		return nil
	}

	// Then load JSON config
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(r); err != nil {
		return err
	}
	return nil
}

func (s *sshSigntest) sign(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: "POST",
		URL:    client.Address() + s.pathPrefix + "/sign/" + s.role,
		Header: s.header,
		Body:   []byte(fmt.Sprintf(`{"public_key": "%s"}`, s.publicKeyRSA)),
	}
}

func setupSSHSign(client *api.Client, randomMounts bool, caConfig *SSHSignerCAConfig, roleConfig *SSHSignerRoleConfig) (*sshSigntest, error) {
	sshSignerPath, err := uuid.GenerateUUID()
	if err != nil {
		panic("can't create UUID")
	}
	if !randomMounts {
		sshSignerPath = "ssh-signer"
	}

	// Enable SSH Secrets Engine
	err = client.Sys().Mount(sshSignerPath, &api.MountInput{
		Type: "ssh",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling ssh: %v", err)
	}

	// Write Config for CA
	sshCAConfigPath := filepath.Join(sshSignerPath, "config", "ca")
	_, err = client.Logical().Write(sshCAConfigPath, map[string]interface{}{
		"generate_signing_key": caConfig.GenerateSigningKey,
		"private_key":          caConfig.PrivateKey,
		"public_key":           caConfig.PublicKey,
		"key_type":             caConfig.KeyType,
		"key_bits":             caConfig.KeyBits,
	})

	if err != nil {
		return nil, fmt.Errorf("error generating signing key: %v", err)
	}

	// Create Role
	role := "benchmark-role"
	if roleConfig.Name != "" {
		role = roleConfig.Name
	}
	rolePath := filepath.Join(sshSignerPath, "roles", role)
	_, err = client.Logical().Write(rolePath, map[string]interface{}{
		"key":                      roleConfig.Key,
		"admin_user":               roleConfig.AdminUser,
		"default_user":             roleConfig.DefaultUser,
		"default_user_template":    roleConfig.DefaultUserTemplate,
		"cidr_list":                roleConfig.CIDRList,
		"exclude_cidr_list":        roleConfig.ExcludeCIDRList,
		"port":                     roleConfig.Port,
		"key_type":                 roleConfig.KeyType,
		"key_bits":                 roleConfig.KeyBits,
		"install_script":           roleConfig.InstallScript,
		"allowed_users":            roleConfig.AllowedUsers,
		"allower_users_template":   roleConfig.AllowedUsersTemplate,
		"allowed_domains":          roleConfig.AllowedDomains,
		"key_option_specs":         roleConfig.KeyOptionSpecs,
		"ttl":                      roleConfig.TTL,
		"max_ttl":                  roleConfig.MaxTTL,
		"allowed_critical_options": roleConfig.AllowedCriticalOptions,
		"allowed_extensions":       roleConfig.AllowedExtensions,
		"default_critical_options": roleConfig.DefaultCriticalOptions,
		"default_extensions":       roleConfig.DefaultExtensions,
		"allow_user_certificates":  roleConfig.AllowUserCertificates,
		"allow_host_certificates":  roleConfig.AllowHostCertificates,
		"allow_bare_domains":       roleConfig.AllowBareDomains,
		"allow_subdomains":         roleConfig.AllowSubdomains,
		"allow_user_key_ids":       roleConfig.AllowUserKeyIDs,
		"key_id_format":            roleConfig.KeyIDFormat,
		"allowed_user_key_lengths": roleConfig.AllowedUserKeyLengths,
		"algorithm_signer":         roleConfig.AlgorithmSigner,
		"not_before_duration":      roleConfig.NotBeforeDuration,
	})

	if err != nil {
		return nil, fmt.Errorf("error creating ssh signer role %q: %v", role, err)
	}

	// Generate Public Key to sign
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("error generating test RSA key-pair: %v", err)
	}

	// Get Public
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("error generating test RSA public key: %v", err)
	}

	publicKeyRSA := "ssh-rsa " + base64.StdEncoding.EncodeToString(publicKey.Marshal())

	return &sshSigntest{
		header:       http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
		pathPrefix:   "/v1/" + filepath.Join(sshSignerPath),
		role:         role,
		publicKeyRSA: publicKeyRSA,
	}, nil
}
