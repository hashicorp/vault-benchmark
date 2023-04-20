package benchmarktests

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Constants for test
const (
	CertAuthTestType   = "cert_auth"
	CertAuthTestMethod = "POST"
)

func init() {
	// "Register" this test to the main test registry
	TestList[CertAuthTestType] = func() BenchmarkBuilder { return &CertAuth{} }
}

type CertAuth struct {
	pathPrefix string
	header     http.Header
	config     *CertAuthTestConfig
	logger     hclog.Logger
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
	Name                       string   `hcl:"name"`
	Certificate                string   `hcl:"certificate,optional"`
	AllowedNames               string   `hcl:"allowed_names,optional"`
	AllowedCommonNames         []string `hcl:"allowed_common_names,optional"`
	AllowedDNSSANS             []string `hcl:"allowed_dns_sans,optional"`
	AllowedEmailSANS           []string `hcl:"allowed_email_sans,optional"`
	AllowedURISANS             []string `hcl:"allowed_uri_sans,optional"`
	AllowedOrganizationalUnits []string `hcl:"allowed_organizational_units,optional"`
	RequiredExtensions         []string `hcl:"required_extensions,optional"`
	AllowedMetadataExtensions  []string `hcl:"allowed_metadata_extensions,optional"`
	DisplayName                string   `hcl:"display_name,optional"`
	TokenTTL                   string   `hcl:"token_ttl,optional"`
	TokenMaxTTL                string   `hcl:"token_max_ttl,optional"`
	TokenPolicies              []string `hcl:"token_policies,optional"`
	Policies                   []string `hcl:"policies,optional"`
	TokenBoundCIDRs            []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL        string   `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy       bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses               int      `hcl:"token_num_uses,optional"`
	TokenPeriod                string   `hcl:"token_period,optional"`
	TokenType                  string   `hcl:"token_type,optional"`
}

func (c *CertAuth) ParseConfig(body hcl.Body) error {
	c.config = &CertAuthTestConfig{
		Config: &CertAuthRoleConfig{
			Name: "benchmark-vault",
		},
	}

	diags := gohcl.DecodeBody(body, nil, c.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (c *CertAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CertAuthTestMethod,
		URL:    client.Address() + c.pathPrefix + "/login",
		Header: c.header,
	}
}

func (c *CertAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CertAuthTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CertAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := c.config.Config
	c.logger = targetLogger.Named(CertAuthTestType)

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	if config.Certificate == "" {
		// Create self-signed CA
		c.logger.Warn("no CA provided; creating self-signed CA")
		benchCA, err := GenerateCA()
		if err != nil {
			log.Fatalf("error generating benchmark CA: %v", err)
		}

		// Generate Client cert for Cert Auth
		c.logger.Trace("creating client cert")
		clientCert, clientKey, err := GenerateCert(benchCA.Template, benchCA.Signer)
		if err != nil {
			log.Fatalf("error generating client cert: %v", err)
		}

		// Create X509 Key Pair
		c.logger.Trace("generating x509 key pair")
		keyPair, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			log.Fatalf("error generating client key pair: %v", err)
		}

		// Create new client with newly generated cert
		c.logger.Trace("creating new client with generated cert")
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
	c.logger.Trace(mountLogMessage("auth", "cert", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling cert auth: %v", err)
	}

	setupLogger := c.logger.Named(authPath)

	// Decode config into map to pass with request
	setupLogger.Trace(parsingConfigLogMessage("role"))
	roleData, err := structToMap(config)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Set up role
	setupLogger.Trace(writingLogMessage("role"), "name", config.Name)
	rolePath := filepath.Join("auth", authPath, "certs", config.Name)
	_, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		return nil, fmt.Errorf("error creating cert role %q: %v", config.Name, err)
	}

	return &CertAuth{
		pathPrefix: "/v1/auth/" + authPath,
		header:     generateHeader(client),
		logger:     c.logger,
	}, nil
}

func (c *CertAuth) Cleanup(client *api.Client) error {
	c.logger.Trace(cleanupLogMessage(c.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(c.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (c *CertAuth) Flags(fs *flag.FlagSet) {}
