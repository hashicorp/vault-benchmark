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
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	IdentityTestType = "identity"

	// Attack-phase workload modes selected via the workload config field.
	identityWorkloadNone      = "none"
	identityWorkloadLogin     = "login"
	identityWorkloadGroupRead = "group_read"

	// Placeholder attack target used when workload = none. The framework always
	// drives an attack for the configured duration, so a seed-only run hits this
	// cheap health check rather than performing identity work.
	identityNoWorkloadPath = "/v1/sys/health"

	// Default random-sample size for login-resolution validation. A sample of
	// 100 aliases gives a high probability (>99%) of detecting corruption
	// affecting 5% or more of mappings, independent of entity_count.
	identityValidationSamples = 100
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityTestType] = func() BenchmarkBuilder { return &Identity{} }
}

// TODO(refactor-pr):
//   - parallelize entity/group creation with a bounded worker pool (setup is serial)
//   - decouple user count from entity_count (bcrypt cost is pinned to entity_count
//     whenever create_users is set)

// Identity seeds Vault Identity objects (entities, optional groups, and optional
// userpass links) during setup and, when a workload is selected, drives that
// workload during the attack phase. It is the consolidation of the former
// identity_population and identity_group_read targets.
type Identity struct {
	// Attack-phase state, populated by configureAttack.
	method     string
	pathPrefix string
	header     http.Header
	loginBody  []byte

	// Creation-phase state retained for the attack and cleanup.
	runID         string
	entityIDs     []string
	groupIDs      []string
	userpassMount string
	ownsMount     bool

	config *IdentityConfig
	logger hclog.Logger
}

type IdentityConfig struct {
	EntityCount       int    `hcl:"entity_count,optional"`
	NamePrefix        string `hcl:"name_prefix,optional"`
	ProgressInterval  int    `hcl:"progress_interval,optional"`
	Workload          string `hcl:"workload,optional"`
	GroupCount        int    `hcl:"group_count,optional"`
	GroupSize         int    `hcl:"group_size,optional"`
	CreateAliases     bool   `hcl:"create_aliases,optional"`
	CreateUsers       bool   `hcl:"create_users,optional"`
	UserpassMount     string `hcl:"userpass_mount,optional"`
	ValidationSamples int    `hcl:"validation_samples,optional"`
}

func (i *Identity) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityConfig `hcl:"config,block"`
	}{
		Config: &IdentityConfig{
			EntityCount:       1000,
			NamePrefix:        "entity",
			ProgressInterval:  1000,
			Workload:          identityWorkloadNone,
			GroupCount:        0,
			GroupSize:         10,
			CreateAliases:     false,
			CreateUsers:       false,
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
	if i.config.ValidationSamples <= 0 {
		return fmt.Errorf("validation_samples must be greater than 0")
	}

	// Grouping is optional; when requested it must be internally consistent.
	if i.config.GroupCount < 0 {
		return fmt.Errorf("group_count cannot be negative")
	}
	if i.config.GroupCount > 0 {
		if i.config.GroupSize <= 0 {
			return fmt.Errorf("group_size must be greater than 0 when group_count > 0")
		}
		if i.config.GroupSize > i.config.EntityCount {
			return fmt.Errorf("group_size (%d) cannot be greater than entity_count (%d)", i.config.GroupSize, i.config.EntityCount)
		}
	}

	// Auth linking (aliases and/or users) needs a mount to attach to.
	if (i.config.CreateAliases || i.config.CreateUsers) && strings.TrimSpace(i.config.UserpassMount) == "" {
		return fmt.Errorf("userpass_mount cannot be empty when create_aliases or create_users is set")
	}

	// The workload enum drives the attack phase, so each mode must have its
	// prerequisites created during setup.
	switch i.config.Workload {
	case identityWorkloadNone:
		// Seed-only: no attack-phase prerequisites.
	case identityWorkloadLogin:
		if !i.config.CreateUsers {
			return fmt.Errorf("workload %q requires create_users = true so seeded entities are loginable", identityWorkloadLogin)
		}
		if !i.config.CreateAliases {
			return fmt.Errorf("workload %q requires create_aliases = true so logins resolve to seeded entities", identityWorkloadLogin)
		}
	case identityWorkloadGroupRead:
		if i.config.GroupCount <= 0 {
			return fmt.Errorf("workload %q requires group_count > 0", identityWorkloadGroupRead)
		}
	default:
		return fmt.Errorf("invalid workload %q: must be one of %q, %q, or %q",
			i.config.Workload, identityWorkloadNone, identityWorkloadLogin, identityWorkloadGroupRead)
	}

	return nil
}

func (i *Identity) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	// Identity is a built-in path, so this target manages no secret mount.
	_ = mountName

	i.logger = targetLogger.Named(IdentityTestType)
	i.header = generateHeader(client)

	runID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate run id: %w", err)
	}
	i.runID = runID

	randomMounts := topLevelConfig != nil && topLevelConfig.RandomMounts

	authLinker, err := newIdentityAuthLinkHelper(client, identityAuthLinkConfig{
		CreateAliases: i.config.CreateAliases,
		CreateUsers:   i.config.CreateUsers,
		UserpassMount: i.config.UserpassMount,
		RandomMounts:  randomMounts,
	})
	if err != nil {
		return nil, err
	}
	i.userpassMount = authLinker.mountPath()
	// Cleanup only runs when random_mounts is enabled (enforced in run.go), so a
	// linked mount is run-scoped and safe to disable wholesale during cleanup.
	i.ownsMount = (i.config.CreateAliases || i.config.CreateUsers) && randomMounts

	if err := i.createEntities(client, authLinker); err != nil {
		_ = i.Cleanup(client)
		return nil, err
	}

	if i.config.GroupCount > 0 {
		if err := i.createGroups(client); err != nil {
			_ = i.Cleanup(client)
			return nil, err
		}
	}

	if err := i.validateLinks(client, authLinker); err != nil {
		_ = i.Cleanup(client)
		return nil, err
	}

	if err := i.configureAttack(authLinker); err != nil {
		_ = i.Cleanup(client)
		return nil, err
	}

	return i, nil
}

// createEntities creates EntityCount entities, linking each to a userpass user
// and/or alias as configured, and records their ids in creation order.
func (i *Identity) createEntities(client *api.Client, authLinker *identityAuthLinkHelper) error {
	start := time.Now()
	i.logger.Info("entity population start", "total", i.config.EntityCount,
		"create_aliases", i.config.CreateAliases, "create_users", i.config.CreateUsers)

	i.entityIDs = make([]string, 0, i.config.EntityCount)
	for idx := 1; idx <= i.config.EntityCount; idx++ {
		name := i.entityName(idx)

		// The create endpoint returns the id directly, so no read-back is needed.
		resp, err := client.Logical().Write("identity/entity", map[string]any{
			"name": name,
		})
		if err != nil {
			return fmt.Errorf("error creating entity %q: %w", name, err)
		}

		id, err := identityIDFromResponse(resp)
		if err != nil {
			return fmt.Errorf("error reading id for entity %q: %w", name, err)
		}

		i.entityIDs = append(i.entityIDs, id)

		if err := authLinker.linkEntity(client, name, id); err != nil {
			return err
		}

		if idx%i.config.ProgressInterval == 0 || idx == i.config.EntityCount {
			i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", idx, i.config.EntityCount))
		}
	}

	i.logger.Info("entity population complete", "total", i.config.EntityCount, "elapsed", time.Since(start).String())
	return nil
}

// createGroups creates GroupCount internal groups, each populated with GroupSize
// members drawn deterministically from the created entities.
func (i *Identity) createGroups(client *api.Client) error {
	i.groupIDs = make([]string, 0, i.config.GroupCount)
	for idx := 0; idx < i.config.GroupCount; idx++ {
		name := i.groupName(idx)
		members := selectGroupMembers(i.entityIDs, idx, i.config.GroupSize)

		resp, err := client.Logical().Write("identity/group", map[string]any{
			"name":              name,
			"type":              "internal",
			"member_entity_ids": members,
		})
		if err != nil {
			return fmt.Errorf("error creating identity group %q: %w", name, err)
		}

		id, err := identityIDFromResponse(resp)
		if err != nil {
			return fmt.Errorf("error reading id for group %q: %w", name, err)
		}

		i.groupIDs = append(i.groupIDs, id)
	}

	i.logger.Info("group population complete", "total", i.config.GroupCount)
	return nil
}

// validateLinks verifies a random sample of alias mappings by logging in and
// confirming each token resolves to the expected entity. Sampling suffices
// because alias-linking failures are systematic. It is a no-op unless aliases
// were created.
func (i *Identity) validateLinks(client *api.Client, authLinker *identityAuthLinkHelper) error {
	if !i.config.CreateAliases {
		return nil
	}

	sampleCount := min(i.config.ValidationSamples, i.config.EntityCount)
	for _, idx := range sampleIndices(i.config.EntityCount, sampleCount) {
		name := i.entityName(idx)
		if err := authLinker.validateLogin(client, name, i.entityIDs[idx-1]); err != nil {
			return err
		}
	}

	i.logger.Info("login resolution validated", "samples", sampleCount, "entities", i.config.EntityCount)
	return nil
}

// configureAttack sets the method, path, and body used by Target for the
// selected workload.
func (i *Identity) configureAttack(authLinker *identityAuthLinkHelper) error {
	switch i.config.Workload {
	case identityWorkloadLogin:
		// Every login uses the same password, so marshal the body once here
		// rather than per request in the attack loop.
		body, err := json.Marshal(map[string]string{"password": authLinker.password()})
		if err != nil {
			return fmt.Errorf("error encoding login request body: %w", err)
		}
		i.loginBody = body
		i.method = http.MethodPost
		i.pathPrefix = "/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath()))
	case identityWorkloadGroupRead:
		i.method = http.MethodGet
		i.pathPrefix = "/v1/identity/group/id/"
	default: // identityWorkloadNone
		i.method = http.MethodGet
		i.pathPrefix = identityNoWorkloadPath
		i.logger.Warn("workload is \"none\": the attack phase performs no identity work and only hits sys/health for the configured duration; use a short duration for seed-only runs")
	}
	return nil
}

// Target drives the configured workload: userpass logins against generated
// users, reads of random seeded groups, or the no-workload placeholder.
func (i *Identity) Target(client *api.Client) vegeta.Target {
	switch i.config.Workload {
	case identityWorkloadLogin:
		user := i.entityName(rand.Intn(i.config.EntityCount) + 1)
		return vegeta.Target{
			Method: i.method,
			URL:    client.Address() + i.pathPrefix + "/login/" + user,
			Header: i.header,
			Body:   i.loginBody,
		}
	case identityWorkloadGroupRead:
		if len(i.groupIDs) == 0 {
			return vegeta.Target{
				Method: i.method,
				URL:    client.Address() + i.pathPrefix,
				Header: i.header,
			}
		}
		groupID := i.groupIDs[rand.Intn(len(i.groupIDs))]
		return vegeta.Target{
			Method: i.method,
			URL:    client.Address() + i.pathPrefix + groupID,
			Header: i.header,
		}
	default: // identityWorkloadNone
		return vegeta.Target{
			Method: i.method,
			URL:    client.Address() + i.pathPrefix,
			Header: i.header,
		}
	}
}

func (i *Identity) Cleanup(client *api.Client) error {
	i.logger.Trace("cleaning up identity benchmark resources")
	var firstErr error

	for _, groupID := range i.groupIDs {
		if _, err := client.Logical().Delete("identity/group/id/" + groupID); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting identity group %q: %w", groupID, err)
		}
	}

	// Deleting an entity removes its aliases, so aliases need no separate cleanup.
	for _, entityID := range i.entityIDs {
		if _, err := client.Logical().Delete("identity/entity/id/" + entityID); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting identity entity %q: %w", entityID, err)
		}
	}

	// The run-scoped userpass mount holds every linked and probe user, so
	// disabling it removes them all in a single call.
	if i.ownsMount && i.userpassMount != "" {
		if err := client.Sys().DisableAuth(i.userpassMount); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error disabling userpass mount %q: %w", i.userpassMount, err)
		}
	}

	return firstErr
}

func (i *Identity) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     i.method,
		pathPrefix: i.pathPrefix,
	}
}

func (i *Identity) Flags(fs *flag.FlagSet) {}

// entityName derives a run-unique, index-addressable entity name so the attack
// phase can reconstruct usernames from an index without storing a lookup map.
func (i *Identity) entityName(idx int) string {
	return fmt.Sprintf("%s-%s-%06d", i.config.NamePrefix, i.runID, idx)
}

func (i *Identity) groupName(idx int) string {
	return fmt.Sprintf("%s-group-%s-%06d", i.config.NamePrefix, i.runID, idx)
}

// selectGroupMembers returns GroupSize member ids for the given group index,
// wrapping around the entity list so every entity is used roughly evenly.
func selectGroupMembers(entityIDs []string, groupIndex, groupSize int) []string {
	members := make([]string, 0, groupSize)
	start := (groupIndex * groupSize) % len(entityIDs)

	for offset := 0; offset < groupSize; offset++ {
		members = append(members, entityIDs[(start+offset)%len(entityIDs)])
	}

	return members
}
