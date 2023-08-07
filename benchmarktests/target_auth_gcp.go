// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-gcp-common/gcputil"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
	"golang.org/x/oauth2"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

// Constants for test
const (
	GCPAuthTestType     = "gcp_auth"
	GCPAuthTestMethod   = "POST"
	IdentityMetadataURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

func init() {
	// "Register" this test to the main test registry
	TestList[GCPAuthTestType] = func() BenchmarkBuilder { return &GCPAuth{} }
}

type GCPAuth struct {
	pathPrefix string
	roleName   string
	jwt        string
	header     http.Header
	timeout    time.Duration
	config     *GCPAuthTestConfig
	logger     hclog.Logger
}

type GCPAuthTestConfig struct {
	GCPAuthConfig     *GCPAuthConfig     `hcl:"auth,block"`
	GCPTestRoleConfig *GCPTestRoleConfig `hcl:"role,block"`
}

type GCPAuthConfig struct {
	Credentials    string `hcl:"credentials"`
	IAMAlias       string `hcl:"iam_alias,optional"`
	IAMMetadata    string `hcl:"iam_metadata,optional"`
	GCEAlias       string `hcl:"gce_alias,optional"`
	GCEMetadata    string `hcl:"gce_metadata,optional"`
	CustomEndpoint string `hcl:"custom_endpoint,optional"`
}

type GCPTestRoleConfig struct {
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
		Config *GCPAuthTestConfig `hcl:"config,block"`
	}{Config: &GCPAuthTestConfig{
		GCPAuthConfig:     &GCPAuthConfig{},
		GCPTestRoleConfig: &GCPTestRoleConfig{},
	},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	g.config = testConfig.Config
	return nil
}

func (g *GCPAuth) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: GCPAuthTestMethod,
		URL:    client.Address() + g.pathPrefix + "/login",
		Header: g.header,
		Body:   []byte(fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, g.roleName, g.jwt)),
	}
}

func (g *GCPAuth) Cleanup(client *api.Client) error {
	g.logger.Trace(cleanupLogMessage(g.pathPrefix))
	_, err := client.Logical().Delete(strings.Replace(g.pathPrefix, "/v1/", "/sys/", 1))
	if err != nil {
		return fmt.Errorf("error cleaning up mount: %v", err)
	}
	return nil
}

func (g *GCPAuth) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     GCPAuthTestMethod,
		pathPrefix: g.pathPrefix,
	}
}

func (g *GCPAuth) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	g.logger = targetLogger.Named(GCPAuthTestType)

	if topLevelConfig.RandomMounts {
		authPath, err = uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("can't generate UUID for mount name: %v", err)
		}
	}

	g.logger.Trace(mountLogMessage("auth", "gcp", authPath))
	err = client.Sys().EnableAuthWithOptions(authPath, &api.EnableAuthOptions{
		Type: "gcp",
	})
	if err != nil {
		return nil, fmt.Errorf("error enabling gcp: %v", err)
	}
	setupLogger := g.logger.Named(authPath)

	// check if the provided argument should be read from file
	creds := g.config.GCPAuthConfig.Credentials
	if len(creds) > 0 && creds[0] == '@' {
		contents, err := ioutil.ReadFile(creds[1:])
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}

		g.config.GCPAuthConfig.Credentials = string(contents)
	}

	setupLogger.Trace(parsingConfigLogMessage("gcp auth"))
	GCPAuthConfig, err := structToMap(g.config.GCPAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcp auth config from struct: %v", err)
	}

	// Check that JWT TTL is not shorter than benchmark test duration
	parsedTTL, err := time.ParseDuration(g.config.GCPTestRoleConfig.MaxJWTExp)
	if err != nil {
		return nil, fmt.Errorf("error parsing JWT TTL from configuration: %v", err)
	}
	if parsedTTL < topLevelConfig.Duration {
		g.config.GCPTestRoleConfig.MaxJWTExp = topLevelConfig.Duration.String()
		fmt.Printf("GCP role max_jwt_exp (%v) cannot be shorter than benchmark test duration (%v) setting max_jwt_exp to test length (%v)", parsedTTL, topLevelConfig.Duration, topLevelConfig.Duration)
	}

	// Write GCP config
	setupLogger.Trace(writingLogMessage("gcp auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", GCPAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp config: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	GCPRoleConfig, err := structToMap(g.config.GCPTestRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Write GCP Role
	setupLogger.Trace(writingLogMessage("role"), "name", g.config.GCPTestRoleConfig.Name)
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+g.config.GCPTestRoleConfig.Name, GCPRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp role: %v", err)
	}

	jwt, err := getSignedJwt(g.config)
	if err != nil {
		return nil, fmt.Errorf("error fetching JWT: %v", err)
	}

	return &GCPAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		jwt:        jwt,
		roleName:   g.config.GCPTestRoleConfig.Name,
		timeout:    g.timeout,
		logger:     g.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (g *GCPAuth) Flags(fs *flag.FlagSet) {}

func getSignedJwt(config *GCPAuthTestConfig) (string, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cleanhttp.DefaultClient())

	credentials, tokenSource, err := gcputil.FindCredentials(config.GCPAuthConfig.Credentials, ctx, iamcredentials.CloudPlatformScope)
	if err != nil {
		return "", fmt.Errorf("could not obtain credentials: %v", err)
	}

	httpClient := oauth2.NewClient(ctx, tokenSource)

	var serviceAccount string
	// Select one of the configured service accounts if more than 1
	rand.Seed(time.Now().Unix())
	if len(config.GCPTestRoleConfig.BoundServiceAccounts) > 0 {
		n := rand.Int() % len(config.GCPTestRoleConfig.BoundServiceAccounts)
		serviceAccount = config.GCPTestRoleConfig.BoundServiceAccounts[n]
	}

	if serviceAccount == "" && credentials != nil {
		serviceAccount = credentials.ClientEmail
	}

	if config.GCPTestRoleConfig.Type != "iam" {
		// Check if the metadata server is available.
		if !metadata.OnGCE() {
			return "", fmt.Errorf("could not obtain service account from credentials (are you using Application Default Credentials?). You must provide a service account to authenticate as")
		}
		metadataClient := metadata.NewClient(cleanhttp.DefaultClient())
		v := url.Values{}
		v.Set("audience", fmt.Sprintf("http://vault/%s", config.GCPTestRoleConfig.Name))
		v.Set("format", "full")
		path := "instance/service-accounts/default/identity?" + v.Encode()
		instanceJwt, err := metadataClient.Get(path)
		if err != nil {
			return "", fmt.Errorf("unable to read the identity token: %w", err)
		}
		return instanceJwt, nil

	} else {
		ttl := time.Duration(15) * time.Minute
		if config.GCPTestRoleConfig.MaxJWTExp != "" {
			ttl, err = parseutil.ParseDurationSecond(config.GCPTestRoleConfig.MaxJWTExp)
			if err != nil {
				return "", fmt.Errorf("could not parse jwt_exp '%s' into integer value", config.GCPTestRoleConfig.MaxJWTExp)
			}
		}

		jwtPayload := map[string]interface{}{
			"aud": fmt.Sprintf("http://vault/%s", config.GCPTestRoleConfig.Name),
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
}
