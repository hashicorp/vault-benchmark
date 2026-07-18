// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// Identity benchmarks Vault's identity store: setup seeds entities (with optional
// aliases, userpass users, and groups), then the attack drives the selected
// workload. See docs/tests/identity.md for the config surface and rationale.

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"sync/atomic"
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

	// Workload modes selected by the workload config field.
	identityWorkloadPopulate  = "populate"
	identityWorkloadLogin     = "login"
	identityWorkloadGroupRead = "group_read"

	// No-op attack target for the populate workload.
	identityNoWorkloadPath = "/v1/sys/health"

	// Parallel workers for entity/group creation, validation, and cleanup.
	identityConcurrency = 10

	// Progress updates logged per setup phase (roughly quintiles), so the cadence
	// scales with entity count rather than a fixed stride.
	identityProgressDivisions = 5
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityTestType] = func() BenchmarkBuilder { return &Identity{} }
}

// Identity seeds identity objects during setup and drives the workload attack.
// It carries only the state Target/Cleanup read; setup-only data (e.g. entity
// ids) stays local to Setup.
type Identity struct {
	// Standard target fields.
	pathPrefix string // attack URL prefix
	header     http.Header
	config     *IdentityConfig

	// mountName (from the framework) and runID (per-run UUID) seed every run-scoped
	// object name, so Target and Cleanup re-derive names instead of storing them.
	mountName string
	runID     string

	// Attack request state, precomputed in Setup so Target stays a cheap assembler.
	method     string   // HTTP method
	password   string   // shared userpass password for seeded users
	loginBody  []byte   // precomputed login request body (login workload)
	loginUsers int      // resolved login pool, min(login_users, alias_count, entity_count)
	groupIDs   []string // group ids read at random by group_read

	logger hclog.Logger
}

type IdentityConfig struct {
	Workload    string       `hcl:"workload,optional"`
	EntityCount int          `hcl:"entity_count,optional"`
	AliasCount  int          `hcl:"alias_count,optional"`
	LoginUsers  int          `hcl:"login_users,optional"`
	GroupCount  int          `hcl:"group_count,optional"`
	Groups      *GroupConfig `hcl:"groups,block"`

	// TODO(future): aliases -- an allocation block (like groups) that fans entities
	// across multiple userpass mounts for >1 alias/entity (roadmap phase 5).
	// TODO(future): policies -- optional policy attach (mirror userpass token_policies).
}

// GroupConfig shapes how the group_count groups are filled: omit for a balanced
// split, or set a preset, or count+size for a partial allocation.
type GroupConfig struct {
	Preset string `hcl:"preset,optional"` // balanced (default) | empty | full
	Count  int    `hcl:"count,optional"`  // partial: groups that get members
	Size   int    `hcl:"size,optional"`   // partial: members per filled group
}

func (i *Identity) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityConfig `hcl:"config,block"`
	}{
		Config: &IdentityConfig{
			Workload:    identityWorkloadPopulate,
			EntityCount: 1000,
			AliasCount:  0,
			LoginUsers:  100,
			GroupCount:  0,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding to struct: %v", diags)
	}

	c := testConfig.Config
	i.config = c

	// entity_count drives every slice/alloc in setup; a non-positive value is a
	// no-op run (and an illegal make), so it is the one count we guard.
	if c.EntityCount <= 0 {
		return fmt.Errorf("entity_count must be greater than 0")
	}

	// A login user needs an alias to resolve, so the pool is capped at alias_count,
	// and also clamped to entity_count so validateAliases never indexes past the
	// entities that exist (alias_count is intentionally not bounded by entity_count).
	// TODO(future): once the aliases allocation block lands (>1 alias/entity across
	// mounts, like groups), alias_count may exceed entity_count by design; revisit
	// this clamp and the validateAliases indexing so the sample maps to real entities.
	i.loginUsers = min(c.LoginUsers, c.AliasCount, c.EntityCount)

	// Guard each workload's prerequisites so the attack phase can't silently do
	// nothing for the whole run.
	switch c.Workload {
	case identityWorkloadPopulate:
		// Seed only: no prerequisites.
	case identityWorkloadLogin:
		if i.loginUsers <= 0 {
			return fmt.Errorf("workload %q requires login_users > 0 and alias_count > 0 so logins resolve to seeded entities", identityWorkloadLogin)
		}
	case identityWorkloadGroupRead:
		if c.GroupCount <= 0 {
			return fmt.Errorf("workload %q requires group_count > 0", identityWorkloadGroupRead)
		}
	default:
		return fmt.Errorf("invalid workload %q: must be one of %q, %q, or %q",
			c.Workload, identityWorkloadPopulate, identityWorkloadLogin, identityWorkloadGroupRead)
	}

	return nil
}

func (i *Identity) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	// identity is a built-in path, so this target manages no secret mount and
	// ignores topLevelConfig.RandomMounts: there is no user-named mount to
	// randomize, and the per-run UUID baked into every object name already gives
	// each run its own isolated namespace.
	i.logger = targetLogger.Named(IdentityTestType)

	runID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate run id: %w", err)
	}

	result := &Identity{
		config:     i.config,
		logger:     i.logger,
		mountName:  mountName,
		runID:      runID,
		loginUsers: i.loginUsers,
	}

	// A userpass mount is only needed when entities get aliases (users imply
	// aliases, being capped at alias_count); accessor stays empty otherwise.
	var accessor string
	if i.config.AliasCount > 0 {
		accessor, result.password, err = enableUserpass(client, runID)
		if err != nil {
			return nil, err
		}
	}

	entityIDs, err := result.createEntities(client, accessor)
	if err != nil {
		return nil, err
	}

	if i.config.GroupCount > 0 {
		groupFill, groupCap, err := parseGroups(i.config.Groups, i.config.GroupCount, i.config.EntityCount)
		if err != nil {
			return nil, err
		}
		result.groupIDs, err = result.createGroups(client, entityIDs, groupFill, groupCap)
		if err != nil {
			return nil, err
		}
	}

	if i.loginUsers > 0 {
		if err := result.validateAliases(client, entityIDs); err != nil {
			return nil, err
		}
	}

	result.method, result.pathPrefix = configureAttack(i.config, runID)
	if i.config.Workload == identityWorkloadLogin {
		result.loginBody = fmt.Appendf(nil, `{"password": "%s"}`, result.password)
	}
	result.header = generateHeader(client)

	return result, nil
}

// createEntities creates EntityCount entities concurrently: the first AliasCount
// get an alias and the first loginUsers also get a userpass user (loginUsers <=
// alias_count, so every user is aliased). Ids are collected only when a later step
// reads them (groups or validation), each at its index so the slice stays ordered
// without a lock.
func (i *Identity) createEntities(client *api.Client, accessor string) ([]string, error) {
	start := time.Now()
	total := i.config.EntityCount
	i.logger.Info("entity population start", "total", total,
		"aliases", i.config.AliasCount, "login_users", i.loginUsers)

	// Computed once; used only by entities that get a user.
	mountPath := userpassMountPath(i.runID)

	// Skip the entity_count-sized slice unless groups or validation read the ids.
	var entityIDs []string
	if i.config.GroupCount > 0 || i.loginUsers > 0 {
		entityIDs = make([]string, total)
	}

	progressInterval := ceilDiv(total, identityProgressDivisions)
	var done atomic.Int64

	err := runConcurrent(0, total-1, func(idx int) error {
		name := objectName(i.mountName, "entity", i.runID, idx)

		resp, err := client.Logical().Write("identity/entity", map[string]any{
			"name": name,
		})
		if err != nil {
			return fmt.Errorf("error creating identity entity %q: %w", name, err)
		}

		id, err := idFromResponse(resp)
		if err != nil {
			return fmt.Errorf("error reading identity entity id for %q: %w", name, err)
		}

		if entityIDs != nil {
			entityIDs[idx] = id
		}

		if idx < i.config.AliasCount {
			if err := addEntityAlias(client, accessor, name, id); err != nil {
				return err
			}
		}
		if idx < i.loginUsers {
			if err := addUserpassUser(client, mountPath, name, i.password); err != nil {
				return err
			}
		}

		n := done.Add(1)
		if n%int64(progressInterval) == 0 || int(n) == total {
			i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", n, total))
		}
		return nil
	})
	if err != nil {
		return entityIDs, err
	}

	i.logger.Info("entity population complete", "total", total, "elapsed", time.Since(start).String())
	return entityIDs, nil
}

// createGroups creates GroupCount internal groups concurrently. The first
// groupFill groups each get groupCap members drawn deterministically from the
// created entities; any remaining groups are empty (per the allocation).
func (i *Identity) createGroups(client *api.Client, entityIDs []string, groupFill, groupCap int) ([]string, error) {
	start := time.Now()
	total := i.config.GroupCount
	i.logger.Info("group population start", "total", total, "filled", groupFill,
		"members_per_group", groupCap)

	groupIDs := make([]string, total)

	err := runConcurrent(0, total-1, func(idx int) error {
		groupName := objectName(i.mountName, "group", i.runID, idx)
		var members []string
		if idx < groupFill {
			members = selectGroupMembers(entityIDs, idx, groupCap)
		}

		resp, err := client.Logical().Write("identity/group", map[string]any{
			"name":              groupName,
			"type":              "internal",
			"member_entity_ids": members,
		})
		if err != nil {
			return fmt.Errorf("error creating identity group %q: %w", groupName, err)
		}

		id, err := idFromResponse(resp)
		if err != nil {
			return fmt.Errorf("error reading identity group id for %q: %w", groupName, err)
		}

		groupIDs[idx] = id
		return nil
	})
	if err != nil {
		return groupIDs, err
	}

	i.logger.Info("group population complete", "total", total, "elapsed", time.Since(start).String())
	return groupIDs, nil
}

// validateAliases logs in as each of the loginUsers seeded users and confirms the
// token resolves to the expected entity. Concurrent and collect-all: the login
// pool is small (capped at login_users), so verifying every user is cheap.
func (i *Identity) validateAliases(client *api.Client, entityIDs []string) error {
	start := time.Now()
	total := i.loginUsers
	i.logger.Info("login resolution validation start", "users", total)

	mountPath := userpassMountPath(i.runID)

	err := runConcurrent(0, total-1, func(idx int) error {
		name := objectName(i.mountName, "entity", i.runID, idx)
		return validateLogin(client, mountPath, name, i.password, entityIDs[idx])
	})
	if err != nil {
		return err
	}

	i.logger.Info("login resolution validation complete", "users", total, "elapsed", time.Since(start).String())
	return nil
}

// Target builds the request for the configured workload, adjusting the base
// target's URL (and body, for login).
func (i *Identity) Target(client *api.Client) vegeta.Target {
	t := vegeta.Target{
		Method: i.method,
		URL:    client.Address() + i.pathPrefix,
		Header: i.header,
	}

	switch i.config.Workload {
	case identityWorkloadLogin:
		user := objectName(i.mountName, "entity", i.runID, rand.Intn(i.loginUsers))
		t.URL += "/login/" + user
		t.Body = i.loginBody
	case identityWorkloadGroupRead:
		t.URL += i.groupIDs[rand.Intn(len(i.groupIDs))]
	}

	return t
}

func (i *Identity) Cleanup(client *api.Client) error {
	if i.config.Workload == identityWorkloadPopulate {
		i.logger.Info("populate workload; leaving seeded identity objects in place")
		return nil
	}

	start := time.Now()
	i.logger.Info("cleanup start", "groups", len(i.groupIDs), "entities", i.config.EntityCount)

	var allErrs []error

	// Groups are held by id (attack state), so delete by id. Entities aren't kept,
	// so re-derive each name from its index (matching creation) and delete by name,
	// which also drops that entity's aliases. Both re-derive rather than storing keys.
	if err := deleteConcurrent(client, "identity/group/id/", len(i.groupIDs), func(idx int) string {
		return i.groupIDs[idx]
	}); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := deleteConcurrent(client, "identity/entity/name/", i.config.EntityCount, func(idx int) string {
		return objectName(i.mountName, "entity", i.runID, idx)
	}); err != nil {
		allErrs = append(allErrs, err)
	}

	// Disabling the run-scoped userpass mount drops all its users in one call; its
	// path is derived from the run id.
	if i.config.AliasCount > 0 {
		mountPath := userpassMountPath(i.runID)
		if err := client.Sys().DisableAuth(mountPath); err != nil {
			allErrs = append(allErrs, fmt.Errorf("error disabling userpass mount %q: %w", mountPath, err))
		}
	}

	i.logger.Info("cleanup complete", "elapsed", time.Since(start).String())
	return errors.Join(allErrs...)
}

func (i *Identity) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     i.method,
		pathPrefix: i.pathPrefix,
	}
}

func (i *Identity) Flags(fs *flag.FlagSet) {}
