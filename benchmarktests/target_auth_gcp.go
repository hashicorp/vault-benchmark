// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
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
	config     *GCPTestConfig
	logger     hclog.Logger
}

type GCPTestConfig struct {
	Config *GCPAuthTestConfig `hcl:"config,block"`
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
	MaxJWTExp            string   `hcl:"maw_jwt_exp,optional"`
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
	g.config = &GCPTestConfig{
		Config: &GCPAuthTestConfig{
			GCPAuthConfig:     &GCPAuthConfig{},
			GCPTestRoleConfig: &GCPTestRoleConfig{},
		},
	}

	diags := gohcl.DecodeBody(body, nil, g.config)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

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

func (g *GCPAuth) Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error) {
	var err error
	authPath := mountName
	config := g.config.Config
	g.logger = targetLogger.Named(GCPAuthTestType)

	if randomMountName {
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

	setupLogger.Trace(parsingConfigLogMessage("gcp auth"))
	GCPAuthConfig, err := structToMap(config.GCPAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing gcp auth config from struct: %v", err)
	}

	// Write GCP config
	setupLogger.Trace(writingLogMessage("gcp auth config"))
	_, err = client.Logical().Write("auth/"+authPath+"/config", GCPAuthConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp config: %v", err)
	}

	setupLogger.Trace(parsingConfigLogMessage("role"))
	GCPRoleConfig, err := structToMap(config.GCPTestRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing role config from struct: %v", err)
	}

	// Write GCP Role
	setupLogger.Trace(writingLogMessage("role"), "name", config.GCPTestRoleConfig.Name)
	_, err = client.Logical().Write("auth/"+authPath+"/role/"+config.GCPTestRoleConfig.Name, GCPRoleConfig)
	if err != nil {
		return nil, fmt.Errorf("error writing gcp role: %v", err)
	}

	return &GCPAuth{
		header:     generateHeader(client),
		pathPrefix: "/v1/" + filepath.Join("auth", authPath),
		roleName:   g.config.Config.GCPTestRoleConfig.Name,
		timeout:    g.timeout,
		logger:     g.logger,
	}, nil
}

// Func Flags accepts a flag set to assign additional flags defined in the function
func (k *GCPAuth) Flags(fs *flag.FlagSet) {}

func (a *GCPAuth) getJWTFromMetadataService(vaultAddr string) (string, error) {
	if !metadata.OnGCE() {
		return "", fmt.Errorf("GCE metadata service not available")
	}

	// build request to metadata server
	c := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, IdentityMetadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating http request: %w", err)
	}

	req.Header.Add("Metadata-Flavor", "Google")
	q := url.Values{}
	q.Add("audience", fmt.Sprintf("%s/vault/%s", vaultAddr, a.roleName))
	q.Add("format", "full")
	req.URL.RawQuery = q.Encode()
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request to metadata service: %w", err)
	}
	defer resp.Body.Close()

	// get jwt from response
	body, err := ioutil.ReadAll(resp.Body)
	jwt := string(body)
	if err != nil {
		return "", fmt.Errorf("error reading response from metadata service: %w", err)
	}

	return jwt, nil
}

// generate signed JWT token from GCP IAM.
func signJWT(roleName, serviceAccountEmail string) (*credentialspb.SignJwtResponse, error) {
	ctx := context.Background()
	iamClient, err := credentials.NewIamCredentialsClient(ctx) // can pass option.WithCredentialsFile("path/to/creds.json") as second param if GOOGLE_APPLICATION_CREDENTIALS env var not set
	if err != nil {
		return nil, fmt.Errorf("unable to initialize IAM credentials client: %w", err)
	}
	defer iamClient.Close()

	resourceName := fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountEmail)
	jwtPayload := map[string]interface{}{
		"aud": fmt.Sprintf("vault/%s", roleName),
		"sub": serviceAccountEmail,
		"exp": time.Now().Add(time.Minute * 10).Unix(),
	}

	payloadBytes, err := json.Marshal(jwtPayload)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal jwt payload to json: %w", err)
	}

	signJWTReq := &credentialspb.SignJwtRequest{
		Name:    resourceName,
		Payload: string(payloadBytes),
	}

	jwtResp, err := iamClient.SignJwt(ctx, signJWTReq)
	if err != nil {
		return nil, fmt.Errorf("unable to sign JWT: %w", err)
	}

	return jwtResp, nil
}
