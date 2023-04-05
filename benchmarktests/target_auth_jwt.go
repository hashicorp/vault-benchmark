package benchmarktests

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
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
	"gopkg.in/square/go-jose.v2"
	sqjwt "gopkg.in/square/go-jose.v2/jwt"
)

// Constants for test
const (
	JWTAuthTestType          = "jwt_auth"
	JWTAuthTestMethod        = "POST"
	ecdsaPrivKey      string = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKfldwWLPYsHjRL9EVTsjSbzTtcGRu6icohNfIqcb6A+oAoGCCqGSM49
AwEHoUQDQgAE4+SFvPwOy0miy/FiTT05HnwjpEbSq+7+1q9BFxAkzjgKnlkXk5qx
hzXQvRmS4w9ZsskoTZtuUI+XX7conJhzCQ==
-----END EC PRIVATE KEY-----`
	ecdsaPubKey string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4+SFvPwOy0miy/FiTT05HnwjpEbS
q+7+1q9BFxAkzjgKnlkXk5qxhzXQvRmS4w9ZsskoTZtuUI+XX7conJhzCQ==
-----END PUBLIC KEY-----`
)

func init() {
	// "Register" this test to the main test registry
	TestList[JWTAuthTestType] = func() BenchmarkBuilder { return &JWTAuth{} }
}

// JWT Auth Test Struct
type JWTAuth struct {
	pathPrefix string
	role       string
	header     http.Header
	token      string
	config     *JWTTestConfig
}

// Main Config Struct
type JWTTestConfig struct {
	Config *JWTAuthTestConfig `hcl:"config,block"`
}

// Intermediary struct to assist with HCL decoding
type JWTAuthTestConfig struct {
	JWTAuthConfig *JWTAuthConfig `hcl:"auth_config,block"`
	JWTRoleConfig *JWTRoleConfig `hcl:"role_config,block"`
}

// JWT Auth Config
type JWTAuthConfig struct {
	OIDCDiscoveryUrl     string   `hcl:"oidc_discovery_url,optional"`
	OIDCDiscoveryCaPEM   string   `hcl:"oidc_discovery_ca_pem,optional"`
	OIDCClientId         string   `hcl:"oidc_client_id,optional"`
	OIDCClientSecret     string   `hcl:"oidc_client_secret,optional"`
	OIDCResponseMode     string   `hcl:"oidc_response_mode,optional"`
	OIDCResponseTypes    []string `hcl:"oidc_response_types,optional"`
	JWKSUrl              string   `hcl:"jwks_url,optional"`
	JWKSCaPEM            string   `hcl:"jwks_ca_pem,optional"`
	JWTValidationPubKeys []string `hcl:"jwt_validation_pubkeys,optional"`
	BoundIssuer          string   `hcl:"bound_issuer,optional"`
	JWTSupportedAlgs     []string `hcl:"jwt_supported_algs,optional"`
	DefaultRole          string   `hcl:"default_role,optional"`
	ProviderConfig       string   `hcl:"provider_config,optional"`
	NamespaceInState     bool     `hcl:"namespace_in_state,optional"`
}

// JWT Role Config
type JWTRoleConfig struct {
	Name                 string                 `hcl:"name,optional"`
	RoleType             string                 `hcl:"role_type,optional"`
	BoundAudiences       string                 `hcl:"bound_audiences,optional"`
	UserClaim            string                 `hcl:"user_claim,optional"`
	UserClaimJSONPointer string                 `hcl:"user_claim_json_pointer,optional"`
	ClockSkewLeeway      int                    `hcl:"clock_skew_leeway,optional"`
	ExpirationLeeway     int                    `hcl:"expiration_leeway,optional"`
	NotBeforeLeeway      int                    `hcl:"not_before_leeway,optional"`
	BoundSubject         string                 `hcl:"bound_subject,optional"`
	BoundClaims          map[string]interface{} `hcl:"bound_claims,optional"`
	BoundClaimsType      string                 `hcl:"bound_claims_type,optional"`
	GroupsClaim          string                 `hcl:"groups_claim,optional"`
	ClaimMappings        map[string]string      `hcl:"claim_mappings,optional"`
	OIDCScopes           []string               `hcl:"oidc_scopes,optional"`
	AllowedRedirectUris  []string               `hcl:"allowed_redirect_uris,optional"`
	VerboseOIDCLogging   bool                   `hcl:"verbose_oidc_logging,optional"`
	MaxAge               int                    `hcl:"max_age,optional"`
	TokenTTL             string                 `hcl:"token_ttl,optional"`
	TokenMaxTTL          string                 `hcl:"token_max_ttl,optional"`
	TokenPolicies        []string               `hcl:"token_policies,optional"`
	Policies             []string               `hcl:"policies,optional"`
	TokenBoundCidrs      []string               `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  string                 `hcl:"token_explicit_max_ttl,optional"`
	TokenNoDefaultPolicy bool                   `hcl:"token_no_default_policy,optional"`
	TokenNumUses         int                    `hcl:"token_num_uses,optional"`
	TokenPeriod          string                 `hcl:"token_period,optional"`
	TokenType            string                 `hcl:"token_type,optional"`
}

// ParseConfig parses the passed in hcl.Body into Configuration structs for use during
// test configuration in Vault. Any default configuration definitions for required
// parameters will be set here.
func (j *JWTAuth) ParseConfig(body hcl.Body) error {
	j.config = &JWTTestConfig{
		Config: &JWTAuthTestConfig{
			JWTRoleConfig: &JWTRoleConfig{
				Name:           "benchmark-role",
				RoleType:       "jwt",
				BoundAudiences: "https://vault.plugin.auth.jwt.test",
				UserClaim:      "https://vault/user",
			},
			JWTAuthConfig: &JWTAuthConfig{
				BoundIssuer: "https://team-vault.auth0.com/",
			},
		},
	}

	diags := gohcl.DecodeBody(body, nil, j.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	return nil
}

func (j *JWTAuth) Target(client *api.Client) vegeta.Target {
	// print the API call url
	result := vegeta.Target{
		Method: JWTAuthTestMethod,
		URL:    client.Address() + j.pathPrefix + "/login",
		Header: j.header,
		Body:   []byte(fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, j.role, j.token)),
	}
	return result
}

func (j *JWTAuth) Cleanup(client *api.Client) error {
	_, err := client.Logical().Delete(strings.Replace(j.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (j *JWTAuth) GetTargetInfo() TargetInfo {
	tInfo := TargetInfo{
		method:     JWTAuthTestMethod,
		pathPrefix: j.pathPrefix,
	}
	return tInfo
}

func (j *JWTAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := j.config.Config

	if randomMountName {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("can't create UUID")
		}
	}

	// Create JWT Auth mount
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "jwt",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling jwt: %v", err)
	}

	// Decode JWTRoleConfig struct into mapstructure to pass with request
	jwtRoleConfig, err := structToMap(config.JWTRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding jwt auth config from struct: %v", err)
	}

	// Default `jwt_validation_pubkeys` if neither `jwt_validation_pubkeys`, `jwks_url` nor `oidc_discovery_url` are set
	if config.JWTAuthConfig.JWTValidationPubKeys == nil && config.JWTAuthConfig.JWKSUrl == "" && config.JWTAuthConfig.OIDCDiscoveryUrl == "" {
		config.JWTAuthConfig.JWTValidationPubKeys = []string{ecdsaPubKey}
	}

	// Decode JWTAuthConfig struct into mapstructure to pass with request
	jwtAuthConfig, err := structToMap(config.JWTAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding jwt auth config from struct: %v", err)
	}

	// Write JWT config
	_, err = client.Logical().Write("auth/"+authPath+"/config", jwtAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing JWT config: %v", err)
	}

	// Write JWT role
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+config.JWTRoleConfig.Name, jwtRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing JWT role: %v", err)
	}

	jwtData, _ := j.getTestJWT(ecdsaPrivKey)

	return &JWTAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		role:       config.JWTRoleConfig.Name,
		token:      jwtData,
	}, nil
}

func (j *JWTAuth) Flags(fs *flag.FlagSet) {}

func (j *JWTAuth) getTestJWT(privKey string) (string, *ecdsa.PrivateKey) {
	config := j.config.Config

	cl := sqjwt.Claims{
		Subject:   config.JWTRoleConfig.BoundSubject,
		Issuer:    config.JWTAuthConfig.BoundIssuer,
		NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		Audience:  sqjwt.Audience{config.JWTRoleConfig.BoundAudiences},
	}

	privateCl := struct {
		User   string `json:"https://vault/user"`
		Groups string `json:"https://vault/groups"`
	}{
		config.JWTRoleConfig.UserClaim,
		config.JWTRoleConfig.GroupsClaim,
	}

	var key *ecdsa.PrivateKey
	block, _ := pem.Decode([]byte(privKey))
	if block != nil {
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		log.Fatal(err)
	}

	raw, err := sqjwt.Signed(sig).Claims(cl).Claims(privateCl).CompactSerialize()
	if err != nil {
		log.Fatal(err)
	}

	return raw, key
}
