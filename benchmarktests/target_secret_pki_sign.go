package benchmarktests

import (
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	PKISignTestType   = "pki_sign"
	PKISignTestMethod = "POST"
)

func init() {
	TestList[PKISignTestType] = func() BenchmarkBuilder { return &PKISignTest{} }
}

type PKISignTest struct {
	pathPrefix string
	cn         string
	intpath    string
	rootpath   string
	config     *pkiSignTestConfig
	body       []byte
	header     http.Header
}

type pkiSignTestConfig struct {
	Config *pkiSecretIssueTestConfig `hcl:"config,block"`
}

type pkiSecretIssueTestConfig struct {
	SetupDelay            string               `hcl:"setup_delay,optional"`
	RootCAConfig          *pkiSignRootConfig   `hcl:"root_ca,block"`
	IntermediateCSRConfig *pkiSignIntCSRConfig `hcl:"intermediate_csr,block"`
	IntermediateCAConfig  *pkiSignIntCAConfig  `hcl:"intermediate_ca,block"`
	RoleConfig            *pkiSignRoleConfig   `hcl:"role,block"`
	SignConfig            *pkiSignCSRConfig    `hcl:"sign,block"`
}

// PKISignCertConfig is the configuration
// for the cert to be signed
//
// /pki/sign/:name
type pkiSignCSRConfig struct {
	Name                 string  `hcl:"name,optional"`
	CSR                  *string `hcl:"csr,optional"`
	CommonName           string  `hcl:"common_name,optional"`
	AltNames             string  `hcl:"alt_names,optional"`
	IPSANS               string  `hcl:"ip_sans,optional"`
	URISANS              string  `hcl:"uri_sans,optional"`
	OtherSANS            string  `hcli:"other_sans,optional"`
	TTL                  string  `hcl:"ttl,optional"`
	Format               string  `hcl:"format,optional"`
	ExcludeCNFromSANS    bool    `hcl:"exclude_cn_from_sans,optional"`
	NotAfter             string  `hcl:"not_after,optional"`
	RemoveRootsFromChain bool    `hcl:"remove_root_from_chain,optional"`
	UserIDs              string  `hcl:"user_ids,optional"`
}

// PKISignCAConfig is the configuration
// for the root CA cert to be generated
// for the test
//
// /pki/root/generate/:type
type pkiSignRootConfig struct {
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
	Country             string `hcl:"countrty,optional"`
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

// PKISignIntConfig is the configuratio
// for the intermediate CSR to be
// generated for the test
//
// /pki/intermediate/generate/:type
type pkiSignIntCSRConfig struct {
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
	Country             string `hcl:"countrty,optional"`
	Locality            string `hcl:"locality,optional"`
	Province            string `hcl:"province,optional"`
	StreetAddress       string `hcl:"street_address,optional"`
	PostalCode          string `hcl:"postal_code,optional"`
	SerialNumber        string `hcl:"serial_number,optional"`
	AddBasicConstraints bool   `hcl:"add_basic_constraints,optional"`
	ManagedKeyName      string `hcl:"managed_key_name,optional"`
	ManagedKeyID        string `hcl:"managed_key_id,optional"`
}

// PKISignIntCAConfig is the configuration
// for the signing operation of the intermediate
// CA CSR.
//
// /pki/root/sign-intermediate
type pkiSignIntCAConfig struct {
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
type pkiSignRoleConfig struct {
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

func (p *PKISignTest) ParseConfig(body hcl.Body) error {
	p.config = &pkiSignTestConfig{
		Config: &pkiSecretIssueTestConfig{
			SetupDelay: "1s",
			RootCAConfig: &pkiSignRootConfig{
				Type:       "internal",
				CommonName: "example.com",
			},
			IntermediateCSRConfig: &pkiSignIntCSRConfig{
				Type:       "internal",
				CommonName: "example.com Intermediate Authority",
			},
			IntermediateCAConfig: &pkiSignIntCAConfig{
				Format: "pem_bundle",
			},
			RoleConfig: &pkiSignRoleConfig{
				Name:            "benchmark-sign",
				AllowSubdomains: true,
				AllowAnyName:    true,
				TTL:             "5m",
			},
			SignConfig: &pkiSignCSRConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, p.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (p *PKISignTest) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: PKISignTestMethod,
		URL:    client.Address() + p.pathPrefix,
		Body:   p.body,
		Header: p.header,
	}
}

func (p *PKISignTest) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     PKISignTestMethod,
		pathPrefix: p.pathPrefix,
	}
}

func (p *PKISignTest) Cleanup(client *api.Client) error {
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

func (p *PKISignTest) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
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

	// CSR parsing / creation
	if config.SignConfig.CSR == nil {
		tCSR, err := p.generateTestCSR()
		if err != nil {
			return nil, fmt.Errorf("error generating test csr: %v", err)
		}
		config.SignConfig.CSR = &tCSR
	} else {
		// Check to see if its a path or a string and handle it
		if ok, err := IsFile(*config.SignConfig.CSR); ok {
			csrBytes, err := os.ReadFile(*config.SignConfig.CSR)
			if err != nil {
				return nil, fmt.Errorf("error parsing CSR from file: %v", err)
			}
			csrString := string(csrBytes)
			config.SignConfig.CSR = &csrString
		} else {
			return nil, err
		}
	}

	// Decode Signing Config
	signingData, err := structToMap(config.SignConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding issue config from struct: %v", err)
	}

	signingDataString, err := json.Marshal(signingData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling issue config data: %v", err)
	}

	return &PKISignTest{
		pathPrefix: "/v1/" + path,
		cn:         config.SignConfig.CommonName,
		header:     generateHeader(client),
		body:       []byte(signingDataString),
		rootpath:   p.rootpath,
		intpath:    p.intpath,
	}, nil
}

func (p *PKISignTest) createRootCA(cli *api.Client, pfx string) error {
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

func (p *PKISignTest) createIntermediateCA(cli *api.Client, pfx string) (string, error) {
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

	return filepath.Join(intPath, "sign", config.RoleConfig.Name), nil
}

func (p *PKISignTest) generateTestCSR() (string, error) {
	cBundle := &certutil.CreationBundle{
		Params: &certutil.CreationParameters{
			Subject: pkix.Name{
				CommonName:         "test.vault.benchmark",
				Country:            []string{"US"},
				Organization:       []string{"Hashicorp"},
				Locality:           []string{"San Francisco"},
				OrganizationalUnit: []string{"VaultBenchmarking"},
			},
			KeyType:  "rsa",
			KeyBits:  2048,
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

func (p *PKISignTest) Flags(fs *flag.FlagSet) {}
