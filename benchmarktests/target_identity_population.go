// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
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

	// Placeholder attack target for setup-only mode (link_auth =
	// false); population creates no load of its own.
	identityPopulationNoWorkloadPath = "/v1/sys/health"

	// Default random-sample size for login-resolution validation.
	// A sample of 100 identities provides a high probability (>99%)
	// of detecting corruption affecting 5% or more of mappings.
	identityValidationSamples = 100
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityPopulationTestType] = func() BenchmarkBuilder { return &IdentityPopulation{} }
}

// TODO(refactor-pr):
//   - rename name_prefix default "seed-entity" -> "entity"
//   - decouple user count from entity_count (optional users arg; today 1:1 pins
//     bcrypt cost to entity_count)
//   - warn (don't guard) when link_auth=false at weight<100 (no-op Target is just
//     sys/health noise; link_auth=true at partial weight is a valid mix)
//   shared with identity_group_read:
//   - parallelize entity creation with a bounded worker pool (setup is serial)
//   - allow cleanup with deterministic mounts (identity cleanup never deletes the
//     userpass mount, unlike the global run.go:280 guard assumes)
//   - consolidate with identity_group_read once renamed

// Identity Population Test Struct
type IdentityPopulation struct {
	pathPrefix string
	method     string
	header     http.Header
	config     *IdentityPopulationConfig
	logger     hclog.Logger
	loginBody  []byte
}

type IdentityPopulationConfig struct {
	EntityCount       int    `hcl:"entity_count,optional"`
	NamePrefix        string `hcl:"name_prefix,optional"`
	ProgressInterval  int    `hcl:"progress_interval,optional"`
	LinkAuth          bool   `hcl:"link_auth,optional"`
	UserpassMount     string `hcl:"userpass_mount,optional"`
	ValidationSamples int    `hcl:"validation_samples,optional"`
}

func (i *IdentityPopulation) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityPopulationConfig `hcl:"config,block"`
	}{
		Config: &IdentityPopulationConfig{
			EntityCount:       10000,
			NamePrefix:        "seed-entity",
			ProgressInterval:  1000,
			LinkAuth:          false,
			UserpassMount:     "userpass",
			ValidationSamples: identityValidationSamples,
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

	if i.config.ValidationSamples <= 0 {
		return fmt.Errorf("validation_samples must be greater than 0")
	}

	return nil
}

func (i *IdentityPopulation) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	// Identity is a built-in path, so this target manages no secret mount
	_ = mountName

	i.logger = targetLogger.Named(IdentityPopulationTestType)
	i.header = generateHeader(client)

	authLinker, err := newIdentityAuthLinkHelper(client, identityAuthLinkConfig{
		CreateAliases: i.config.LinkAuth,
		CreateUsers:   i.config.LinkAuth,
		UserpassMount: i.config.UserpassMount,
		RandomMounts:  topLevelConfig != nil && topLevelConfig.RandomMounts,
	})
	if err != nil {
		return nil, err
	}

	entityIDs, err := i.createEntities(client, authLinker)
	if err != nil {
		return nil, err
	}

	return i.buildAttack(client, authLinker, entityIDs)
}

// createEntities creates EntityCount entities, linking each to a userpass user
// and alias when LinkAuth is set, and returns their ids in creation order.
func (i *IdentityPopulation) createEntities(client *api.Client, authLinker *identityAuthLinkHelper) ([]string, error) {
	start := time.Now()
	i.logger.Info("entity population start", "total", i.config.EntityCount, "link_auth", i.config.LinkAuth)

	entityIDs := make([]string, 0, i.config.EntityCount)
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

		entityIDs = append(entityIDs, id)

		if err := authLinker.linkEntity(client, entityName, id); err != nil {
			return nil, err
		}

		if idx%i.config.ProgressInterval == 0 || idx == i.config.EntityCount {
			i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", idx, i.config.EntityCount))
		}
	}

	i.logger.Info("entity population complete", "total", i.config.EntityCount, "elapsed", time.Since(start).String())
	return entityIDs, nil
}

// buildAttack returns the benchmark for the attack phase. Without LinkAuth it is
// a no-workload placeholder; with it, links are first validated by sampled logins
// and the attack drives real userpass logins.
func (i *IdentityPopulation) buildAttack(client *api.Client, authLinker *identityAuthLinkHelper, entityIDs []string) (BenchmarkBuilder, error) {
	population := &IdentityPopulation{
		method:     "GET",
		pathPrefix: identityPopulationNoWorkloadPath,
		header:     i.header,
		config:     i.config,
		logger:     i.logger,
	}

	if !i.config.LinkAuth {
		return population, nil
	}

	// verify login resolves to the expected entity; sampling
	// suffices since linking failures are systematic.
	sampleCount := min(i.config.ValidationSamples, i.config.EntityCount)
	for _, idx := range sampleIndices(i.config.EntityCount, sampleCount) {
		name := i.entityName(idx)
		if err := authLinker.validateLogin(client, name, entityIDs[idx-1]); err != nil {
			return nil, err
		}
	}
	i.logger.Info("login resolution validated", "samples", sampleCount, "entities", i.config.EntityCount)

	// Every login uses the same password, so marshal the body once here
	// rather than per request in the attack loop.
	loginBody, err := json.Marshal(map[string]string{"password": authLinker.password()})
	if err != nil {
		return nil, fmt.Errorf("error encoding login request body: %w", err)
	}

	population.loginBody = loginBody
	population.method = "POST"
	population.pathPrefix = "/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath()))

	return population, nil
}

// Target sends userpass logins against generated users when link_auth
// is enabled; otherwise it hits the no-workload placeholder.
func (i *IdentityPopulation) Target(client *api.Client) vegeta.Target {
	if !i.config.LinkAuth {
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
		Body:   i.loginBody,
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
