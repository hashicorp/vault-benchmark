// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	IdentityPopulationTestType = "identity_population"

	// No-workload placeholder for the attack phase when link_userpass_auth is
	// false. The runner always requires a target, but pure population has no
	// attack of its own; pair this target with another for real load.
	identityPopulationNoWorkloadPath = "/v1/sys/health"
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityPopulationTestType] = func() BenchmarkBuilder { return &IdentityPopulation{} }
}

// Identity Population Test Struct
type IdentityPopulation struct {
	pathPrefix string
	method     string
	header     http.Header
	config     *IdentityPopulationConfig
	logger     hclog.Logger
	entityIDs  []string
	linkAuth   bool
	password   string
}

type IdentityPopulationConfig struct {
	EntityCount      int    `hcl:"entity_count,optional"`
	NamePrefix       string `hcl:"name_prefix,optional"`
	ProgressInterval int    `hcl:"progress_interval,optional"`
	LinkUserpassAuth bool   `hcl:"link_userpass_auth,optional"`
	UserpassMount    string `hcl:"userpass_mount,optional"`
}

func (i *IdentityPopulation) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityPopulationConfig `hcl:"config,block"`
	}{
		Config: &IdentityPopulationConfig{
			EntityCount:      10000,
			NamePrefix:       "seed-entity",
			ProgressInterval: 1000,
			LinkUserpassAuth: false,
			UserpassMount:    "userpass",
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	i.config = testConfig.Config

	if i.config.EntityCount <= 0 {
		return fmt.Errorf("entity_count must be greater than 0")
	}

	if i.config.ProgressInterval <= 0 {
		return fmt.Errorf("progress_interval must be greater than 0")
	}

	if i.config.NamePrefix == "" {
		return fmt.Errorf("name_prefix cannot be empty")
	}

	if strings.TrimSpace(i.config.UserpassMount) == "" {
		return fmt.Errorf("userpass_mount cannot be empty")
	}

	return nil
}

func (i *IdentityPopulation) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	// Identity is a built-in path, so this target manages no secret mount;
	// mountName is required by the interface but unused here.
	_ = mountName

	i.logger = targetLogger.Named(IdentityPopulationTestType)
	i.header = generateHeader(client)
	i.entityIDs = make([]string, 0, i.config.EntityCount)

	authLinker, err := newIdentityAuthLinkHelper(client, identityAuthLinkConfig{
		CreateAliases: i.config.LinkUserpassAuth,
		CreateUsers:   i.config.LinkUserpassAuth,
		UserpassMount: i.config.UserpassMount,
		RandomMounts:  topLevelConfig != nil && topLevelConfig.RandomMounts,
	})
	if err != nil {
		return nil, err
	}

	start := time.Now()
	i.logger.Info("entity population start", "total", i.config.EntityCount, "link_userpass_auth", i.config.LinkUserpassAuth)

	for idx := 1; idx <= i.config.EntityCount; idx++ {
		entityName := i.entityName(idx)

		entityPath := filepath.ToSlash("identity/entity/name/" + entityName)
		_, err := client.Logical().Write(entityPath, map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("error creating entity %q: %w", entityName, err)
		}

		// The create-by-name endpoint can return data=nil, so read back to get id.
		readSec, err := client.Logical().Read(entityPath)
		if err != nil {
			return nil, fmt.Errorf("error reading entity %q after create: %w", entityName, err)
		}

		id, err := identityIDFromResponse(readSec)
		if err != nil {
			return nil, fmt.Errorf("error reading id for entity %q: %w", entityName, err)
		}

		i.entityIDs = append(i.entityIDs, id)

		if err := authLinker.linkEntityAuth(client, entityName, id); err != nil {
			return nil, err
		}

		if idx%i.config.ProgressInterval == 0 || idx == i.config.EntityCount {
			i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", idx, i.config.EntityCount))
		}
	}

	i.logger.Info("entity population complete", "total", i.config.EntityCount, "elapsed", time.Since(start).String())

	// Default to setup-only: no-workload placeholder attack.
	population := &IdentityPopulation{
		method:     "GET",
		pathPrefix: identityPopulationNoWorkloadPath,
		header:     i.header,
		config:     i.config,
		logger:     i.logger,
		entityIDs:  i.entityIDs,
	}

	if i.config.LinkUserpassAuth {
		// A bare userpass login always resolves to some entity, so validate
		// against the expected id to confirm the alias mapping is correct.
		firstUser := i.entityName(1)
		if err := i.validateLoginResolution(client, authLinker, firstUser, i.entityIDs[0]); err != nil {
			return nil, err
		}
		i.logger.Info("login resolution validated", "user", firstUser, "entity_id", i.entityIDs[0])

		population.linkAuth = true
		population.password = authLinker.password()
		population.method = "POST"
		population.pathPrefix = "/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath()))
	}

	return population, nil
}

// validateLoginResolution logs in as one user and confirms it resolves to the
// expected entity, a fail-fast check that the alias mapping is wired correctly.
func (i *IdentityPopulation) validateLoginResolution(client *api.Client, authLinker *identityAuthLinkHelper, user, expectedEntityID string) error {
	loginPath := filepath.ToSlash(filepath.Join("auth", authLinker.mountPath(), "login", user))
	secret, err := client.Logical().Write(loginPath, map[string]any{
		"password": authLinker.password(),
	})
	if err != nil {
		return fmt.Errorf("login resolution check failed for user %q: %w", user, err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("login resolution check for user %q returned no auth data", user)
	}
	if secret.Auth.EntityID != expectedEntityID {
		return fmt.Errorf("login for user %q resolved to entity %q, expected %q",
			user, secret.Auth.EntityID, expectedEntityID)
	}

	return nil
}

// Target sends userpass logins against generated users when link_userpass_auth
// is enabled; otherwise it hits the no-workload placeholder.
func (i *IdentityPopulation) Target(client *api.Client) vegeta.Target {
	if !i.linkAuth {
		return vegeta.Target{
			Method: i.method,
			URL:    client.Address() + i.pathPrefix,
			Header: i.header,
		}
	}

	user := i.entityName(rand.Intn(i.config.EntityCount) + 1)
	return vegeta.Target{
		Method: i.method,
		URL:    client.Address() + i.pathPrefix + "/login/" + user,
		Header: i.header,
		Body:   []byte(fmt.Sprintf(`{"password": "%s"}`, i.password)),
	}
}

func (i *IdentityPopulation) Cleanup(client *api.Client) error {
	_ = client
	// TODO: cleanup is intentionally deferred in this MVP.
	return nil
}

func (i *IdentityPopulation) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     i.method,
		pathPrefix: i.pathPrefix,
	}
}

func (i *IdentityPopulation) Flags(fs *flag.FlagSet) {}

func (i *IdentityPopulation) entityName(idx int) string {
	return fmt.Sprintf("%s-%06d", i.config.NamePrefix, idx)
}
