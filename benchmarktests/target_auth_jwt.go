// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v3"
	sqjwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	JWTAuthTestType   = "jwt_auth"
	JWTAuthTestMethod = "POST"
)

func init() {
	TestList[JWTAuthTestType] = func() BenchmarkBuilder { return &JWTAuth{} }
}

type JWTAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *JWTAuthConfig
	logger     hclog.Logger
}

type JWTAuthConfig struct {
	JWTAuthMountConfig *JWTAuthMountConfig `hcl:"auth,block"`
	JWTAuthRoleConfig *JWTAuthRoleConfig `hcl:"role,block"`
}

type JWTAuthMountConfig struct {
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
	NamespaceInState     *bool    `hcl:"namespace_in_state,optional"`
}

type JWTAuthRoleConfig struct {
	Name                 string                 `hcl:"name,optional"`
	RoleType             string                 `hcl:"role_type,optional"`
	BoundAudiences       []string               `hcl:"bound_audiences,optional"`
	UserClaim            string                 `hcl:"user_claim,optional"`
	UserClaimJSONPointer string                 `hcl:"user_claim_json_pointer,optional"`
	ClockSkewLeeway      int                    `hcl:"clock_skew_leeway,optional"`
	ExpirationLeeway     int                    `hcl:"expiration_leeway,optional"`
	NotBeforeLeeway      int                    `hcl:"not_before_leeway,optional"`
	BoundSubject         string                 `hcl:"bound_subject,optional"`
	BoundClaims          map[string]any `hcl:"bound_claims,optional"`
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

func (j *JWTAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *JWTAuthConfig `hcl:"config,block"`
	}{
		Config: &JWTAuthConfig{
			JWTAuthRoleConfig: &JWTAuthRoleConfig{
				Name:           "benchmark-role",
				RoleType:       "jwt",
				BoundAudiences: []string{"https://vault.plugin.auth.jwt.test"},
				UserClaim:      "https://vault/user",
			},
			JWTAuthMountConfig: &JWTAuthMountConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}
	j.config = testConfig.Config
	return nil
}

func (j *JWTAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	j.logger = targetLogger.Named(JWTAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	j.logger.Trace(mountLogMessage("auth", "jwt", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "jwt",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling jwt: %v", err)
	}

	setupLogger := j.logger.Named(authPath)

	setupLogger.Trace("generating ecdsa keys")
	privKey, pubKey, err := generateECDSAKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating ECDSA keys: %w", err)
	}

	if j.config.JWTAuthMountConfig.JWTValidationPubKeys == nil && j.config.JWTAuthMountConfig.JWKSUrl == "" && j.config.JWTAuthMountConfig.OIDCDiscoveryUrl == "" {
		setupLogger.Trace("jwt_validation_pubkeys, jwks_url, and oidc_discovery_url are empty, using internally generated keys")
		j.config.JWTAuthMountConfig.JWTValidationPubKeys = []string{pubKey}
	}

	setupLogger.Trace(parsingConfigLogMessage("jwt auth"))
	if err := writeStruct(client, "auth/"+authPath+"/config", j.config.JWTAuthMountConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, "auth/"+authPath+"/role/"+j.config.JWTAuthRoleConfig.Name, j.config.JWTAuthRoleConfig); err != nil {
		return nil, err
	}

	setupLogger.Trace("generating test jwt")
	jwtData, err := j.getTestJWT(privKey)
	if err != nil {
		return nil, fmt.Errorf("error generating test JWT: %w", err)
	}

	return &JWTAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		body:       fmt.Appendf(nil, `{"role": "%s", "jwt": "%s"}`, j.config.JWTAuthRoleConfig.Name, jwtData),
		logger:     j.logger,
	}, nil
}

func (j *JWTAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: JWTAuthTestMethod,
		URL:    client.Address() + j.pathPrefix + "/login",
		Header: j.header,
		Body:   j.body,
	}
}

func (j *JWTAuth) Cleanup(client *api.Client) error {
	return cleanupMount(j.logger, client, j.pathPrefix)
}

func (j *JWTAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     JWTAuthTestMethod,
		pathPrefix: j.pathPrefix,
	}
}

func (j *JWTAuth) Flags(fs *flag.FlagSet) {}

func (j *JWTAuth) getTestJWT(privKey string) (string, error) {
	cl := sqjwt.Claims{
		Subject:   j.config.JWTAuthRoleConfig.BoundSubject,
		Issuer:    j.config.JWTAuthMountConfig.BoundIssuer,
		NotBefore: sqjwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		Expiry:    sqjwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		Audience:  append(sqjwt.Audience{}, j.config.JWTAuthRoleConfig.BoundAudiences...),
	}

	privateCl := struct {
		User   string `json:"https://vault/user"`
		Groups string `json:"https://vault/groups"`
	}{
		j.config.JWTAuthRoleConfig.UserClaim,
		j.config.JWTAuthRoleConfig.GroupsClaim,
	}

	var key *ecdsa.PrivateKey
	block, _ := pem.Decode([]byte(privKey))
	if block != nil {
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("error parsing EC private key: %w", err)
		}
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("error creating JWT signer: %w", err)
	}

	raw, err := sqjwt.Signed(sig).Claims(cl).Claims(privateCl).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error serializing JWT: %w", err)
	}

	return raw, nil
}

func generateECDSAKeys() (string, string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode ECDSA private key: %w", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode ECDSA public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(privKeyPEM), string(pubKeyPEM), nil
}
