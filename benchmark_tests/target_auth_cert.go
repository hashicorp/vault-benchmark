package benchmark_tests

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
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

// Constants for test
const CertAuthTestType = "cert_auth"
const CertAuthTestMethod = "POST"

func init() {
	// "Register" this test to the main test registry
	TestList[CertAuthTestType] = func() BenchmarkBuilder { return &cert_auth{} }
}

type cert_auth struct {
	pathPrefix string
	header     http.Header
	config     *CertAuthTestConfig
	clientCert *tls.Certificate
}

type CaCert struct {
	PEM      string
	Template *x509.Certificate
	Signer   crypto.Signer
}

// Main config struct
type CertAuthTestConfig struct {
	Config *CertAuthRoleConfig `hcl:"config,block"`
}

// Cert Auth Role Config
type CertAuthRoleConfig struct {
	Name                       string   `hcl:"name" mapstructure:",omitempty"`
	Certificate                string   `hcl:"certificate,optional" mapstructure:",omitempty"`
	AllowedNames               string   `hcl:"allowed_names,optional" mapstructure:",omitempty"`
	AllowedCommonNames         []string `hcl:"allowed_common_names,optional" mapstructure:",omitempty"`
	AllowedDNSSANS             []string `hcl:"allowed_dns_sans,optional" mapstructure:",omitempty"`
	AllowedEmailSANS           []string `hcl:"allowed_email_sans,optional" mapstructure:",omitempty"`
	AllowedURISANS             []string `hcl:"allowed_uri_sans,optional" mapstructure:",omitempty"`
	AllowedOrganizationalUnits []string `hcl:"allowed_organizational_units,optional" mapstructure:",omitempty"`
	RequiredExtensions         []string `hcl:"required_extensions,optional" mapstructure:",omitempty"`
	AllowedMetadataExtensions  []string `hcl:"allowed_metadata_extensions,optional" mapstructure:",omitempty"`
	DisplayName                string   `hcl:"display_name,optional" mapstructure:",omitempty"`
	TokenTTL                   string   `hcl:"token_ttl,optional" mapstructure:",omitempty"`
	TokenMaxTTL                string   `hcl:"token_max_ttl,optional" mapstructure:",omitempty"`
	TokenPolicies              []string `hcl:"token_policies,optional" mapstructure:",omitempty"`
	Policies                   []string `hcl:"policies,optional" mapstructure:",omitempty"`
	TokenBoundCIDRs            []string `hcl:"token_bound_cidrs,optional" mapstructure:",omitempty"`
	TokenExplicitMaxTTL        string   `hcl:"token_explicit_max_ttl,optional" mapstructure:",omitempty"`
	TokenNoDefaultPolicy       bool     `hcl:"token_no_default_policy,optional" mapstructure:",omitempty"`
	TokenNumUses               int      `hcl:"token_num_uses,optional" mapstructure:",omitempty"`
	TokenPeriod                string   `hcl:"token_period,optional" mapstructure:",omitempty"`
	TokenType                  string   `hcl:"token_type,optional" mapstructure:",omitempty"`
}

func (c *cert_auth) ParseConfig(body hcl.Body) {
	c.config = &CertAuthTestConfig{
		Config: &CertAuthRoleConfig{},
	}

	diags := gohcl.DecodeBody(body, nil, c.config)
	if diags.HasErrors() {
		fmt.Println(diags)
	}
}

func (c *cert_auth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CertAuthTestMethod,
		URL:    client.Address() + c.pathPrefix + "/login",
		Header: c.header,
	}
}

func (c *cert_auth) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     CertAuthTestMethod,
		pathPrefix: c.pathPrefix,
	}
	return tInfo
}

func (c *cert_auth) SetCert(cert *tls.Certificate) {
	c.clientCert = cert
}

func (c *cert_auth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := c.config.Config

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			panic("can't create UUID")
		}
	}

	if c.config.Config.Certificate == "" {
		// Create self-signed CA
		benchCA, err := GenerateCA()
		if err != nil {
			log.Fatalf("error generating benchmark CA: %v", err)
		}

		// Generate Client cert for Cert Auth
		clientCert, clientKey, err := GenerateCert(benchCA.Template, benchCA.Signer)
		if err != nil {
			log.Fatalf("error generating client cert: %v", err)
		}

		// Create X509 Key Pair
		keyPair, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			log.Fatalf("error generating client key pair: %v", err)
		}

		// Create new client with newly generated cert
		tClientConfig := client.CloneConfig()
		tClientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{keyPair}

		nClient, err := api.NewClient(tClientConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to configure vault client with client cert: %v", err)
		}
		nClient.SetToken(client.Token())

		config.Certificate = clientCert

		// TODO: This only will work for one cert auth test since we're using this new client
		// We should invesitage how we can give each test its own client.
		// Set the client to the new client with the newly generated client cert
		client = nClient

	}

	// Create Cert Auth mount
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling cert auth: %v", err)
	}

	// Decode config into map to pass with request
	roleData, err := structToMap(config)
	if err != nil {
		return nil, fmt.Errorf("error decoding role config from struct: %v", err)
	}

	// Set up role
	rolePath := filepath.Join("auth", authPath, "certs", config.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating cert role %q: %v", config.Name, err)
	}

	return &cert_auth{
		pathPrefix: "/v1/auth/" + authPath,
		header:     http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{client.Headers().Get("X-Vault-Namespace")}},
	}, nil
}

func (c *cert_auth) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}
