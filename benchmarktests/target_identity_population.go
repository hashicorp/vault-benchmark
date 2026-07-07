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

	// identityPopulationNoWorkloadPath is a harmless placeholder the attack phase
	// hits when link_userpass_auth is false. The benchmark runner always requires
	// a target, but pure entity population is a setup-only workflow with no
	// meaningful attack of its own, so we issue a cheap health check rather than
	// invent load. Pair this target with another target for real workload.
	identityPopulationNoWorkloadPath = "/v1/sys/health"
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityPopulationTestType] = func() BenchmarkBuilder { return &IdentityPopulation{} }
}

// IdentityPopulation creates a static identity entity dataset during Setup.
//
// It has one intent-level flag, link_userpass_auth:
//   - false (default): a setup-only population workflow. It seeds entities and
//     nothing else; the attack phase is a no-workload placeholder (see
//     identityPopulationNoWorkloadPath). Pair with another target for load.
//   - true: it additionally makes the entities loginable (userpass user + entity
//     alias) and drives login traffic in the attack phase, so benchmark traffic
//     exercises Vault identity resolution end to end.
type IdentityPopulation struct {
	pathPrefix string
	method     string
	header     http.Header
	config     *IdentityPopulationConfig
	logger     hclog.Logger

	entityIDs []string

	linkAuth  bool
	mountPath string
	password  string

	count int
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
	// Identity is a built-in path, so this target does not create a secret mount.
	// The interface requires this arg for all targets.
	_ = mountName

	i.logger = targetLogger.Named(IdentityPopulationTestType)
	i.header = generateHeader(client)
	i.entityIDs = make([]string, 0, i.config.EntityCount)

	// A single flag drives the whole identity-auth workflow: creating the
	// userpass user and the entity alias are implementation details of making
	// an entity loginable, not independent knobs.
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

		if readSec == nil || readSec.Data == nil {
			return nil, fmt.Errorf("empty response reading entity %q after create", entityName)
		}

		val, ok := readSec.Data["id"]
		if !ok {
			return nil, fmt.Errorf("missing id for entity %q", entityName)
		}

		id, ok := val.(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("invalid id for entity %q", entityName)
		}

		i.entityIDs = append(i.entityIDs, id)

		if err := authLinker.linkEntityAuth(client, entityName, id); err != nil {
			return nil, err
		}

		i.count = idx

		if idx%i.config.ProgressInterval == 0 || idx == i.config.EntityCount {
			i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", idx, i.config.EntityCount))
		}
	}

	i.logger.Info("entity population", "complete", fmt.Sprintf("%d/%d", i.count, i.config.EntityCount), "elapsed", time.Since(start).String())

	// Default: setup-only population. The attack phase is a no-workload
	// placeholder because the runner always requires a target.
	population := &IdentityPopulation{
		method:     "GET",
		pathPrefix: identityPopulationNoWorkloadPath,
		header:     i.header,
		config:     i.config,
		logger:     i.logger,
		entityIDs:  i.entityIDs,
		count:      i.count,
	}

	if i.config.LinkUserpassAuth {
		// One-shot smoke check proving the user->alias->entity mapping resolves.
		// A bare userpass login always returns some entity id (Vault auto-creates
		// one), so this must compare against the expected id to be meaningful.
		firstUser := i.entityName(1)
		if err := i.validateLoginResolution(client, authLinker, firstUser, i.entityIDs[0]); err != nil {
			return nil, err
		}
		i.logger.Info("login resolution validated", "user", firstUser, "entity_id", i.entityIDs[0])

		population.linkAuth = true
		population.mountPath = authLinker.mountPath()
		population.password = authLinker.password()
		population.method = "POST"
		population.pathPrefix = "/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath()))
	}

	return population, nil
}

// validateLoginResolution logs in as user and confirms the login resolves to the
// expected entity.
//
// Purpose: verify alias mapping correctness (user -> alias -> entity is wired up).
// Not: exhaustively validate all generated users. This is a single fail-fast
// smoke check on one representative user; broad login coverage is the attack
// phase's job.
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

// Target drives login traffic against the generated users when link_userpass_auth
// is enabled, so benchmark traffic exercises identity resolution. Otherwise this
// is a setup-only population workflow and the attack is a no-workload placeholder
// (see identityPopulationNoWorkloadPath); pair with another target for real load.
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
