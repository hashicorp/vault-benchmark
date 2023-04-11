package benchmarktests

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	PKIIssueTestType   = "pki_issue"
	PKIIssueTestMethod = "POST"
)

func init() {
	TestList[PKIIssueTestType] = func() BenchmarkBuilder { return &PKIIssueTest{} }
}

type PKIIssueTest struct {
	pathPrefix string
	cn         string
	intpath    string
	rootpath   string
	config     *PKIIssueTestConfig
	body       []byte
	header     http.Header
}

type PKIIssueTestConfig struct {
	Config *PKISecretIssueTestConfig `hcl:"config,block"`
}

type PKISecretIssueTestConfig struct {
	SetupDelay            string                `hcl:"setup_delay,optional"`
	RootCAConfig          *PKIIssueRootConfig   `hcl:"root_ca,block"`
	IntermediateCSRConfig *PKIIssueIntCSRConfig `hcl:"intermediate_csr,block"`
	IntermediateCAConfig  *PKIIssueIntCAConfig  `hcl:"intermediate_ca,block"`
	RoleConfig            *PKIIssueRoleConfig   `hcl:"role,block"`
	IssueConfig           *PKIIssueCertConfig   `hcl:"issue,block"`
}

// PKIIssueCertConfig is the configuration
// for the cert to be issued
//
// /pki/issue/:name
type PKIIssueCertConfig struct {
	Name              string `hcl:"name,optional"`
	CommonName        string `hcl:"common_name,optional"`
	AltNames          string `hcl:"alt_names,optional"`
	IPSANS            string `hcl:"ip_sans,optional"`
	URISANS           string `hcl:"uri_sans,optional"`
	OtherSANS         string `hcli:"other_sans,optional"`
	TTL               string `hcl:"ttl,optional"`
	Format            string `hcl:"format,optional"`
	PrivateKeyFormat  string `hcl:"private_key_format,optional"`
	ExcludeCNFromSANS bool   `hcl:"exclude_cn_from_sans,optional"`
	NotAfter          string `hcl:"not_after,optional"`
	UserIDs           string `hcl:"user_ids,optional"`
}

// PKIIssueCAConfig is the configuration
// for the root CA cert to be generated
// for the test
//
// /pki/root/generate/:type
type PKIIssueRootConfig struct {
	Type                string `hcl:"type,optional"`
	IssuerName          string `hcl:"issuer_name,optional"`
	KeyName             string `hcl:"key_name,optional"`
	KeyRef              string `hcl:"key_ref,optional"`
	CommonName          string `hcl:"common_name,optional"`
	AltNames            string `hcl:"alt_names,optional"`
	IPSANS              string `hcl:"ip_sans,optional"`
	URISANS             string `hcl:"uri_sans,optional"`
	OtherSANS           string `hcl:"other_sans,optional"`
	TTL                 string `hcl:"ttl,optional"`
	Format              string `hcl:"format,optional"`
	PrivateKeyFormat    string `hcl:"private_key_format,optional"`
	KeyType             string `hcl:"key_type,optional"`
	KeyBits             int    `hcl:"key_bits,optional"`
	MaxPathLength       int    `hcl:"max_path_length,optional"`
	ExcludeCNFromSANS   bool   `hcl:"exclude_cn_from_sans,optional"`
	PermittedDNSDomains string `hcl:"permitted_dns_domains,optional"`
	OU                  string `hcl:"ou,optional"`
	Organization        string `hcl:"organization,optional"`
	Country             string `hcl:"country,optional"`
	Locality            string `hcl:"locality,optional"`
	Province            string `hcl:"province,optional"`
	StreetAddress       string `hcl:"street_address,optional"`
	PostalCode          string `hcl:"postal_code,optional"`
	SerialNumber        string `hcl:"serial_number,optional"`
	NotBeforeDuration   string `hcl:"not_before_duration,optional"`
	NotAfter            string `hcl:"not_after,optional"`
	ManagedKeyName      string `hcl:"managed_key_name,optional"`
	ManagedKeyID        string `hcl:"managed_key_id,optional"`
}

// PKIIssueIntConfig is the configuratio
// for the intermediate CSR to be
// generated for the test
//
// /pki/intermediate/generate/:type
type PKIIssueIntCSRConfig struct {
	Type                string `hcl:"type,optional"`
	CommonName          string `hcl:"common_name,optional"`
	AltNames            string `hcl:"alt_names,optional"`
	IPSANS              string `hcl:"ip_sans,optional"`
	URISANS             string `hcl:"uri_sans,optional"`
	OtherSANS           string `hcl:"other_sans,optional"`
	Format              string `hcl:"format,optional"`
	PrivateKeyFormat    string `hcl:"private_key_format,optional"`
	KeyType             string `hcl:"key_type,optional"`
	KeyBits             int    `hcl:"key_bits,optional"`
	KeyName             string `hcl:"key_name,optional"`
	KeyRef              string `hcl:"key_ref,optional"`
	SignatureBits       int    `hcl:"signature_bits,optional"`
	ExcludeCNFromSANS   bool   `hcl:"exclude_cn_from_sans,optional"`
	OU                  string `hcl:"ou,optional"`
	Organization        string `hcl:"organization,optional"`
	Country             string `hcl:"country,optional"`
	Locality            string `hcl:"locality,optional"`
	Province            string `hcl:"province,optional"`
	StreetAddress       string `hcl:"street_address,optional"`
	PostalCode          string `hcl:"postal_code,optional"`
	SerialNumber        string `hcl:"serial_number,optional"`
	AddBasicConstraints bool   `hcl:"add_basic_constraints,optional"`
	ManagedKeyName      string `hcl:"managed_key_name,optional"`
	ManagedKeyID        string `hcl:"managed_key_id,optional"`
}

// PKIIssueIntCAConfig is the configuration
// for the signing operation of the intermediate
// CA CSR.
//
// /pki/root/sign-intermediate
type PKIIssueIntCAConfig struct {
	CSR                 string `hcl:"csr,optional"`
	CommonName          string `hcl:"common_name,optional"`
	AltNames            string `hcl:"alt_names,optional"`
	IPSANS              string `hcl:"ip_sans,optional"`
	URISANS             string `hcl:"uri_sans,optional"`
	OtherSANS           string `hcl:"other_sans,optional"`
	TTL                 string `hcl:"ttl,optional"`
	Format              string `hcl:"format,optional"`
	MaxPathLength       int    `hcl:"max_path_length,optional"`
	UseCSRValues        bool   `hcl:"use_csr_values,optional"`
	PermittedDNSDomains string `hcl:"permitted_dns_domains,optional"`
	OU                  string `hcl:"ou,optional"`
	Organization        string `hcl:"organization,optional"`
	Country             string `hcl:"countrty,optional"`
	Locality            string `hcl:"locality,optional"`
	Province            string `hcl:"province,optional"`
	StreetAddress       string `hcl:"street_address,optional"`
	PostalCode          string `hcl:"postal_code,optional"`
	SerialNumber        string `hcl:"serial_number,optional"`
	NotBeforeDuration   string `hcl:"not_before_duration,optional"`
	NotAfter            string `hcl:"not_after,optional"`
	SignatureBits       int    `hcl:"signature_bits,optional"`
	SKID                string `hcl:"skid,optional"`
	UsePSS              bool   `hcl:"use_pss,optional"`
}

// PKI Role config defining how the issued cert
// should be configured
//
// /pki/roles/:name
type PKIIssueRoleConfig struct {
	Name                         string   `hcl:"name,optional"`
	TTL                          string   `hcl:"ttl,optional"`
	MaxTTL                       string   `hcl:"max_ttl,optional"`
	AllowLocalhost               *bool    `hcl:"allow_localhost,optional"`
	AllowedDomains               []string `hcl:"allowed_domains,optional"`
	AllowedDomainsTemplate       bool     `hcl:"allowed_domain_template,optional"`
	AllowBareDomains             bool     `hcl:"allow_bare_domains,optional"`
	AllowSubdomains              bool     `hcl:"allow_subdomains,optional"`
	AllowGlobDomains             bool     `hcl:"allow_glob_domains,optional"`
	AllowWildcardCertificates    *bool    `hcl:"allow_wildcard_certificates,optional"`
	AllowAnyName                 bool     `hcl:"allow_any_name,optional"`
	EnforceHostnames             *bool    `hcl:"enforce_hostnames,optional"`
	AllowIPSANS                  *bool    `hcl:"allow_ip_sans,optional"`
	AllowedURISANS               string   `hcl:"allowed_uri_sans,optional"`
	AllowedURISANSTemplate       bool     `hcl:"allowed_uri_sans_template,optional"`
	AllowedOtherSANS             string   `hcl:"allowed_other_sans,optional"`
	AllowedSerialNumbers         string   `hcl:"allowed_serial_numbers,optional"`
	ServerFlag                   *bool    `hcl:"server_flag,optional"`
	ClientFlag                   *bool    `hcl:"client_flag,optional"`
	CodeSigningFlag              bool     `hcl:"code_signing_flag,optional"`
	EmailProtectionFlag          bool     `hcl:"email_protection_flag,optional"`
	KeyType                      string   `hcl:"key_type,optional"`
	KeyBits                      int      `hcl:"key_bits,optional"`
	SignatureBits                int      `hcl:"signature_bits,optional"`
	UsePSS                       bool     `hcl:"use_pss,optional"`
	KeyUsage                     []string `hcl:"key_usage,optional"`
	ExtKeyUsage                  []string `hcl:"ext_key_usage,optional"`
	ExtKeyUsageOIDS              string   `hcl:"ext_key_usage_oids,optional"`
	UseCSRCommonName             *bool    `hcl:"use_csr_common_name,optional"`
	UseCSRSANS                   *bool    `hcl:"use_csr_sans,optional"`
	OU                           string   `hcl:"ou,optional"`
	Organization                 string   `hcl:"organization,optional"`
	Country                      string   `hcl:"countrty,optional"`
	Locality                     string   `hcl:"locality,optional"`
	Province                     string   `hcl:"province,optional"`
	StreetAddress                string   `hcl:"street_address,optional"`
	PostalCode                   string   `hcl:"postal_code,optional"`
	GenerateLease                bool     `hcl:"generate_lease,optional"`
	NoStore                      bool     `hcl:"no_store,optional"`
	RequireCN                    *bool    `hcl:"require_cn,optional"`
	PolicyIdentifiers            []string `hcl:"policy_identifiers,optional"`
	BasicConstrainsValidForNonCA bool     `hcl:"basic_constraints_valid_for_non_ca,optional"`
	NotBeforeDuration            string   `hcl:"not_before_duration,optional"`
	NotAfter                     string   `hcl:"not_after,optional"`
	CNValidations                []string `hcl:"cn_validations,optional"`
	AllowedUserIDs               string   `hcl:"allowed_user_ids,optional"`
}

func (p *PKIIssueTest) ParseConfig(body hcl.Body) error {
	p.config = &PKIIssueTestConfig{
		Config: &PKISecretIssueTestConfig{
			SetupDelay: "1s",
			RootCAConfig: &PKIIssueRootConfig{
				Type:       "internal",
				CommonName: "example.com",
			},
			IntermediateCSRConfig: &PKIIssueIntCSRConfig{
				Type:       "internal",
				CommonName: "example.com Intermediate Authority",
			},
			IntermediateCAConfig: &PKIIssueIntCAConfig{
				Format: "pem_bundle",
			},
			RoleConfig: &PKIIssueRoleConfig{
				Name:            "benchmark-issue",
				AllowSubdomains: true,
				AllowAnyName:    true,
				TTL:             "5m",
			},
			IssueConfig: &PKIIssueCertConfig{
				CommonName: "test.vault.benchmark",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, p.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (p *PKIIssueTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: PKIIssueTestMethod,
		URL:    client.Address() + p.pathPrefix,
		Body:   p.body,
		Header: p.header,
	}
}

func (p *PKIIssueTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     PKIIssueTestMethod,
		pathPrefix: p.pathPrefix,
	}
}

func (p *PKIIssueTest) Cleanup(client *api.Client) error {
	// Unmount Root
	_, err := client.Logical().Delete(filepath.Join("/sys/mounts/", p.rootpath))
	if err != nil {
		return fmt.Errorf("error cleaning up root mount: %v", err)
	}

	// Unmount Intermediate
	_, err = client.Logical().Delete(filepath.Join("/sys/mounts/", p.intpath))
	if err != nil {
		return fmt.Errorf("error cleaning up int mount: %v", err)
	}
	return nil
}

func (p *PKIIssueTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	secretPath := mountName
	config := p.config.Config

	if randomMountName {
		secretPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create Root CA
	err = p.createRootCA(client, secretPath)
	if err != nil {
		return nil, err
	}

	// Create and sign Intermediate CA
	path, err := p.createIntermediateCA(client, secretPath)
	if err != nil {
		return nil, err
	}

	// Decode Issue Config
	issueData, err := structToMap(config.IssueConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding issue config from struct: %v", err)
	}

	issueDataString, err := json.Marshal(issueData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling issue config data: %v", err)
	}

	return &PKIIssueTest{
		pathPrefix: "/v1/" + path,
		cn:         config.IssueConfig.CommonName,
		header:     generateHeader(client),
		body:       []byte(issueDataString),
		rootpath:   p.rootpath,
		intpath:    p.intpath,
	}, nil
}

func (p *PKIIssueTest) createRootCA(cli *api.Client, pfx string) error {
	config := p.config.Config

	// Create PKI Root mount
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
	p.rootpath = rootPath

	// Avoid slow mount setup:
	// URL: PUT $VAULT_ADDR/v1/9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal
	// Code: 404. Errors: * no handler for route "9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal". route entry not found.
	delay, err := time.ParseDuration(config.SetupDelay)
	if err != nil {
		return err
	}
	time.Sleep(delay)

	// Decode Root Config struct into map to pass with request
	rootData, err := structToMap(config.RootCAConfig)
	if err != nil {
		return fmt.Errorf("error decoding root config from struct: %v", err)
	}

	// Setup Root CA
	_, err = cli.Logical().Write(filepath.Join(rootPath, "root", "generate", config.RootCAConfig.Type), rootData)
	if err != nil {
		return err
	}

	_, err = cli.Logical().Write(filepath.Join(rootPath, "config", "urls"), map[string]interface{}{
		"issuing_certificates":    fmt.Sprintf("%s/v1/%s/ca", cli.Address(), rootPath),
		"crl_distribution_points": []string{fmt.Sprintf("%s/v1/%s/crl", cli.Address(), rootPath)},
	})
	return err
}

func (p *PKIIssueTest) createIntermediateCA(cli *api.Client, pfx string) (string, error) {
	config := p.config.Config
	rootPath := fmt.Sprintf("%v-root", pfx)
	intPath := fmt.Sprintf("%v-int", pfx)

	// Create PKI Int Mount
	err := cli.Sys().Mount(intPath, &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil {
		return "", err
	}
	p.intpath = intPath

	// Avoid slow mount setup:
	// URL: PUT $VAULT_ADDR/v1/9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal
	// Code: 404. Errors: * no handler for route "9679cb02-65a4-f625-2f27-68d51e46af46-root/root/generate/internal". route entry not found.
	delay, err := time.ParseDuration(config.SetupDelay)
	if err != nil {
		return "", err
	}
	time.Sleep(delay)

	// Decode Intermediate CSR config to map to pass with request
	intCSRData, err := structToMap(config.IntermediateCSRConfig)
	if err != nil {
		return "", fmt.Errorf("error decoding intermediate csr config from struct: %v", err)
	}

	// Create Intermediate CSR
	resp, err := cli.Logical().Write(filepath.Join(intPath, "intermediate", "generate", config.IntermediateCSRConfig.Type), intCSRData)
	if err != nil {
		return "", err
	}
	config.IntermediateCAConfig.CSR = resp.Data["csr"].(string)

	// Decode Intermediate Signing config to map to pass with request
	intSignData, err := structToMap(config.IntermediateCAConfig)
	if err != nil {
		return "", fmt.Errorf("error decoding intermediate signing config from struct: %v", err)
	}

	resp, err = cli.Logical().Write(filepath.Join(rootPath, "root", "sign-intermediate"), intSignData)
	if err != nil {
		return "", err
	}

	// Set Intermediate signed certificate
	_, err = cli.Logical().Write(filepath.Join(intPath, "intermediate", "set-signed"), map[string]interface{}{
		"certificate": strings.Join([]string{resp.Data["certificate"].(string), resp.Data["issuing_ca"].(string)}, "\n"),
	})
	if err != nil {
		return "", err
	}

	// Decode Role config to map to pass with request
	roleData, err := structToMap(config.RoleConfig)
	if err != nil {
		return "", err
	}

	// Create Role
	_, err = cli.Logical().Write(filepath.Join(intPath, "roles", config.RoleConfig.Name), roleData)
	if err != nil {
		return "", err
	}

	return filepath.Join(intPath, "issue", config.RoleConfig.Name), nil
}

func (p *PKIIssueTest) Flags(fs *flag.FlagSet) {}
