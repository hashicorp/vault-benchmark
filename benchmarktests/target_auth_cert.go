// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	CertAuthTestType   = "cert_auth"
	CertAuthTestMethod = "POST"
)

func init() {
	TestList[CertAuthTestType] = func() BenchmarkBuilder { return &CertAuth{} }
}

type CertAuth struct {
	pathPrefix string
	header     http.Header
	config     *CertAuthRoleConfig
	logger     hclog.Logger
}

type CaCert struct {
	PEM      string
	Template *x509.Certificate
	Signer   crypto.Signer
}

type CertAuthRoleConfig struct {
	Name                       string   `hcl:"name,optional"`
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
	testConfig := &struct {
		Config *CertAuthRoleConfig `hcl:"config,block"`
	}{
		Config: &CertAuthRoleConfig{
			Name: "benchmark-vault",
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	c.config = testConfig.Config
	return nil
}

func (c *CertAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	c.logger = targetLogger.Named(CertAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	if c.config.Certificate == "" {
		c.logger.Warn("no CA provided; creating self-signed CA")
		benchCA, err := GenerateCA()
		if err != nil {
			return nil, fmt.Errorf("error generating benchmark CA: %w", err)
		}

		c.logger.Trace("creating client cert")
		clientCert, clientKey, err := GenerateCert(benchCA.Template, benchCA.Signer)
		if err != nil {
			return nil, fmt.Errorf("error generating client cert: %w", err)
		}

		c.logger.Trace("generating x509 key pair")
		keyPair, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return nil, fmt.Errorf("error generating client key pair: %w", err)
		}

		c.logger.Trace("creating new client with generated cert")
		tClientConfig := client.CloneConfig()
		tClientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{keyPair}

		nClient, err := api.NewClient(tClientConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to configure vault client with client cert: %v", err)
		}
		nClient.SetToken(client.Token())

		c.config.Certificate = clientCert

		// TODO: only the last cert_auth target's TLS config is active when multiple run simultaneously; each needs its own client.
		client = nClient
	}

	c.logger.Trace(mountLogMessage("auth", "cert", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling cert auth: %v", err)
	}

	setupLogger := c.logger.Named(authPath)

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, filepath.Join("auth", authPath, "certs", c.config.Name), c.config); err != nil {
		return nil, err
	}

	return &CertAuth{
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		header:     generateHeader(client),
		logger:     c.logger,
	}, nil
}

func (c *CertAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: CertAuthTestMethod,
		URL:    client.Address() + c.pathPrefix + "/login",
		Header: c.header,
	}
}

func (c *CertAuth) Cleanup(client *api.Client) error {
	return cleanupMount(c.logger, client, c.pathPrefix)
}

func (c *CertAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     CertAuthTestMethod,
		pathPrefix: c.pathPrefix,
	}
}

func (c *CertAuth) Flags(fs *flag.FlagSet) {}
