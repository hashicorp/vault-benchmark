// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
	"golang.org/x/oauth2"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

const (
	GCPAuthTestType     = "gcp_auth"
	GCPAuthTestMethod   = "POST"
	IdentityMetadataURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

func init() {
	TestList[GCPAuthTestType] = func() BenchmarkBuilder { return &GCPAuth{} }
}

type GCPAuth struct {
	pathPrefix string
	header     http.Header
	body       []byte
	config     *GCPAuthConfig
	logger     hclog.Logger
}

type GCPAuthConfig struct {
	GCPAuthMountConfig *GCPAuthMountConfig `hcl:"auth,block"`
	GCPAuthRoleConfig *GCPAuthRoleConfig `hcl:"role,block"`
}

type GCPAuthMountConfig struct {
	Credentials    string `hcl:"credentials"`
	IAMAlias       string `hcl:"iam_alias,optional"`
	IAMMetadata    string `hcl:"iam_metadata,optional"`
	GCEAlias       string `hcl:"gce_alias,optional"`
	GCEMetadata    string `hcl:"gce_metadata,optional"`
	CustomEndpoint string `hcl:"custom_endpoint,optional"`
}

type GCPAuthRoleConfig struct {
	Name                 string   `hcl:"name"`
	Type                 string   `hcl:"type"`
	AddGroupAliases      bool     `hcl:"add_group_aliases,optional"`
	AllowGCEInference    bool     `hcl:"allow_gce_inference,optional"`
	BoundServiceAccounts []string `hcl:"bound_service_accounts,optional"`
	BoundProjects        []string `hcl:"bound_projects,optional"`
	BoundZones           []string `hcl:"bound_zones,optional"`
	BoundRegions         []string `hcl:"bound_regions,optional"`
	BoundInstanceGroups  []string `hcl:"bound_instance_groups,optional"`
	BoundLabels          []string `hcl:"bound_labels,optional"`
	MaxJWTExp            string   `hcl:"max_jwt_exp,optional"`
	TokenBoundCIDRs      []string `hcl:"token_bound_cidrs,optional"`
	TokenExplicitMaxTTL  string   `hcl:"token_explicit_max_ttl,optional"`
	TokenMaxTTL          string   `hcl:"token_max_ttl,optional"`
	TokenNoDefaultPolicy bool     `hcl:"token_no_default_policy,optional"`
	TokenNumUses         int      `hcl:"token_num_uses,optional"`
	TokenPolicies        []string `hcl:"token_policies,optional"`
	TokenPeriod          string   `hcl:"token_period,optional"`
	TokenTTL             string   `hcl:"token_ttl,optional"`
	TokenType            string   `hcl:"token_type,optional"`
}

func (g *GCPAuth) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *GCPAuthConfig `hcl:"config,block"`
	}{Config: &GCPAuthConfig{
		GCPAuthMountConfig:     &GCPAuthMountConfig{},
		GCPAuthRoleConfig: &GCPAuthRoleConfig{},
	},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	g.config = testConfig.Config
	return nil
}

func (g *GCPAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	g.logger = targetLogger.Named(GCPAuthTestType)

	authPath, err = resolveMountPath(authPath, topLevelConfig.RandomMounts)
	if err != nil {
		return nil, err
	}

	g.logger.Trace(mountLogMessage("auth", "gcp", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "gcp",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling gcp: %v", err)
	}
	setupLogger := g.logger.Named(authPath)

	creds := g.config.GCPAuthMountConfig.Credentials
	if len(creds) > 0 && creds[0] == '@' {
		contents, err := os.ReadFile(creds[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}

		g.config.GCPAuthMountConfig.Credentials = string(contents)
	}

	setupLogger.Trace(parsingConfigLogMessage("gcp auth"))
	gcpAuthConfigMap, err := structToMap(g.config.GCPAuthMountConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcp auth config from struct: %v", err)
	}

	// GCP's JWT TTL must cover the full benchmark duration; a shorter TTL would make
	// tokens expire mid-run and cause auth failures on every tick after expiry.
	parsedTTL, err := time.ParseDuration(g.config.GCPAuthRoleConfig.MaxJWTExp)
	if err != nil {
		return nil, fmt.Errorf("error parsing JWT TTL from configuration: %v", err)
	}
	if parsedTTL < topLevelConfig.Duration {
		g.config.GCPAuthRoleConfig.MaxJWTExp = topLevelConfig.Duration.String()
		warnMsg := fmt.Sprintf("max_jwt_exp (%v) cannot be shorter than test duration (%v). Setting max_jwt_exp to %v", parsedTTL, topLevelConfig.Duration, topLevelConfig.Duration)
		setupLogger.Warn(warnMsg)
	}

	setupLogger.Trace(writingLogMessage("gcp auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", gcpAuthConfigMap)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp config: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	if err := writeStruct(client, "auth/"+authPath+"/role/"+g.config.GCPAuthRoleConfig.Name, g.config.GCPAuthRoleConfig); err != nil {
		return nil, err
	}

	jwt, err := getSignedJwt(g.config)
	if err != nil {
		return nil, fmt.Errorf("error fetching JWT: %v", err)
	}

	// TODO: apply cachedBody refresh (see target_auth_aws.go); IAM-path can refresh, GCE-path requires per-tick metadata call.
	return &GCPAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		body:       fmt.Appendf(nil, `{"role": "%s", "jwt": "%s"}`, g.config.GCPAuthRoleConfig.Name, jwt),
		logger:     g.logger,
	}, nil
}

func (g *GCPAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GCPAuthTestMethod,
		URL:    client.Address() + g.pathPrefix + "/login",
		Header: g.header,
		Body:   g.body,
	}
}

func (g *GCPAuth) Cleanup(client *api.Client) error {
	return cleanupMount(g.logger, client, g.pathPrefix)
}

func (g *GCPAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPAuthTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPAuth) Flags(fs *flag.FlagSet) {}

func getSignedJwt(config *GCPAuthConfig) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())

	credentials, tokenSource, err := gcputil.FindCredentials(config.GCPAuthMountConfig.Credentials, ctx, iamcredentials.CloudPlatformScope)
	if err != nil {
		return "", fmt.Errorf("could not obtain credentials: %v", err)
	}

	httpClient := oauth2.NewClient(ctx, tokenSource)

	var serviceAccount string
	if accounts := config.GCPAuthRoleConfig.BoundServiceAccounts; len(accounts) > 0 {
		serviceAccount = accounts[rand.Intn(len(accounts))]
	}

	if serviceAccount == "" && credentials != nil {
		serviceAccount = credentials.ClientEmail
	}

	if config.GCPAuthRoleConfig.Type != "iam" {
		if !metadata.OnGCE() {
			return "", fmt.Errorf("could not obtain service account from credentials (are you using Application Default Credentials?). You must provide a service account to authenticate as")
		}
		metadataClient := metadata.NewClient(cleanhttp.DefaultClient())
		v := url.Values{}
		v.Set("audience", fmt.Sprintf("http://vault/%s", config.GCPAuthRoleConfig.Name))
		v.Set("format", "full")
		path := "instance/service-accounts/default/identity?" + v.Encode()
		instanceJwt, err := metadataClient.Get(path)
		if err != nil {
			return "", fmt.Errorf("unable to read the identity token: %w", err)
		}
		return instanceJwt, nil
	}

	ttl := time.Duration(15) * time.Minute
	if config.GCPAuthRoleConfig.MaxJWTExp != "" {
		ttl, err = parseutil.ParseDurationSecond(config.GCPAuthRoleConfig.MaxJWTExp)
		if err != nil {
			return "", fmt.Errorf("could not parse jwt_exp '%s' into integer value", config.GCPAuthRoleConfig.MaxJWTExp)
		}
	}

	jwtPayload := map[string]any{
		"aud": fmt.Sprintf("http://vault/%s", config.GCPAuthRoleConfig.Name),
		"sub": serviceAccount,
		"exp": time.Now().Add(ttl).Unix(),
	}
	payloadBytes, err := json.Marshal(jwtPayload)
	if err != nil {
		return "", fmt.Errorf("could not convert JWT payload to JSON string: %v", err)
	}

	jwtReq := &iamcredentials.SignJwtRequest{
		Payload: string(payloadBytes),
	}

	iamClient, err := iamcredentials.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return "", fmt.Errorf("could not create IAM client: %v", err)
	}

	resourceName := fmt.Sprintf(gcputil.ServiceAccountCredentialsTemplate, serviceAccount)
	resp, err := iamClient.Projects.ServiceAccounts.SignJwt(resourceName, jwtReq).Do()
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT for %s using given Vault credentials: %v", resourceName, err)
	}

	return resp.SignedJwt, nil
}
