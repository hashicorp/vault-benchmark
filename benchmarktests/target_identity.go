// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	IdentityTestType = "identity"

	identityPassword = "id-pw"

	// Workload modes selected by the workload config field.
	identityWorkloadPopulate  = "populate"
	identityWorkloadLogin     = "login"
	identityWorkloadGroupRead = "group_read"

	// No-op attack target for the populate workload.
	identityNoWorkloadPath = "/v1/sys/health"

	// Parallel workers for entity/group creation, validation, and cleanup.
	// TODO: worth revisiting at true scale -- whether the ceiling is client-side or
	// Vault-internal contention is an empirical question; dynamic sizing may help.
	identityConcurrency = 10

	// Progress updates logged per setup phase (roughly quintiles), so the cadence
	// scales with entity count rather than a fixed stride.
	identityProgressDivisions = 5
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityTestType] = func() BenchmarkBuilder { return &Identity{} }
}

// Identity carries only the state Target/Cleanup read; setup-only data (e.g.
// entity ids) stays local to Setup.
type Identity struct {
	pathPrefix string // attack URL prefix
	header     http.Header
	config     *IdentityConfig

	// mountName (from the framework) and runID (per-run UUID) seed every run-scoped
	// object name, so Target and Cleanup re-derive names instead of storing them.
	mountName string
	runID     string

	// Attack request state, precomputed in Setup so Target stays a cheap assembler.
	method     string   // HTTP method
	loginBody  []byte   // precomputed login request body (login workload)
	loginUsers int      // resolved login pool, min(login_users, alias_count, entity_count)
	groupIDs   []string // live ids for group_read; removing that workload simplifies this + Cleanup

	logger hclog.Logger
}

type IdentityConfig struct {
	Workload    string       `hcl:"workload,optional"`
	EntityCount int          `hcl:"entity_count,optional"`
	AliasCount  int          `hcl:"alias_count,optional"`
	LoginUsers  int          `hcl:"login_users,optional"`
	GroupCount  int          `hcl:"group_count,optional"`
	Groups      *GroupConfig `hcl:"groups,block"`

	// TODO: aliases -- allocation block (like groups) for >1 alias/entity across mounts.
	// TODO: policies -- attach token_policies to entities/groups.
	// TODO: nested groups -- member_group_ids for org-hierarchy shapes (policy resolution walks the tree).
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
	// and clamped to entity_count so validateLogins never indexes out of bounds.
	// TODO: revisit this clamp once aliases block lands (alias_count may exceed entity_count by design).
	i.loginUsers = min(c.LoginUsers, c.AliasCount, c.EntityCount)

	// TODO: guard alias_count/group_count/login_users for non-negative values.
	// TODO: each new workload touches three switches (here, Target, configureAttack); bundle if this grows.
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
		// TODO: no confirmation prompt; objects stay on Vault until manually removed.
		i.logger.Info("populate workload; leaving seeded identity objects in place")
		return nil
	}

	var allErrs []error

	// Groups are held by id (attack state), so delete by id. Entities aren't kept,
	// so re-derive each name from its index (matching creation) and delete by name,
	// which also drops that entity's aliases. Both re-derive rather than storing keys.
	if err := deleteConcurrent(i.logger, "group deletion", client, "identity/group/id/", len(i.groupIDs), func(idx int) string {
		return i.groupIDs[idx]
	}); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := deleteConcurrent(i.logger, "entity deletion", client, "identity/entity/name/", i.config.EntityCount, func(idx int) string {
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

	return errors.Join(allErrs...)
}

func (i *Identity) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     i.method,
		pathPrefix: i.pathPrefix,
	}
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
		accessor, err = enableUserpass(client, runID)
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
		if err := result.validateLogins(client, entityIDs); err != nil {
			return nil, err
		}
	}

	result.method, result.pathPrefix = configureAttack(i.config, runID)
	if i.config.Workload == identityWorkloadLogin {
		result.loginBody = fmt.Appendf(nil, `{"password": "%s"}`, identityPassword)
	}
	result.header = generateHeader(client)

	return result, nil
}

func (i *Identity) Flags(fs *flag.FlagSet) {}

// createEntities creates EntityCount entities concurrently: the first AliasCount
// get an alias and the first loginUsers also get a userpass user (loginUsers <=
// alias_count, so every user is aliased). Ids are collected only when a later step
// reads them, sized to what that step actually needs: every entity when groups
// select members from the full pool (createGroups can land on any entity via
// wraparound), or just the login pool when only validation reads them, since
// nothing else ever indexes past loginUsers. Each id is written at its own index
// so the slice stays ordered without a lock.
func (i *Identity) createEntities(client *api.Client, accessor string) ([]string, error) {
	total := i.config.EntityCount
	mountPath := userpassMountPath(i.runID)

	var entityIDs []string
	switch {
	case i.config.GroupCount > 0:
		entityIDs = make([]string, total)
	case i.loginUsers > 0:
		entityIDs = make([]string, i.loginUsers)
	}

	err := runPhase(i.logger, "entity population", total, func(idx int) error {
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

		if idx < len(entityIDs) {
			entityIDs[idx] = id
		}

		if idx < i.config.AliasCount {
			if err := addEntityAlias(client, accessor, name, id); err != nil {
				return err
			}
		}
		if idx < i.loginUsers {
			if err := addUserpassUser(client, mountPath, name); err != nil {
				return err
			}
		}
		return nil
	}, "aliases", i.config.AliasCount, "login_users", i.loginUsers)
	if err != nil {
		return entityIDs, err
	}

	return entityIDs, nil
}

// createGroups creates GroupCount internal groups concurrently. The first
// groupFill groups each get groupCap members drawn deterministically from the
// created entities; any remaining groups are empty (per the allocation).
func (i *Identity) createGroups(client *api.Client, entityIDs []string, groupFill, groupCap int) ([]string, error) {
	total := i.config.GroupCount
	groupIDs := make([]string, total)

	err := runPhase(i.logger, "group population", total, func(idx int) error {
		groupName := objectName(i.mountName, "group", i.runID, idx)
		var members []string
		if idx < groupFill {
			members = selectGroupMembers(entityIDs, idx, groupCap)
		}

		// TODO: member_group_ids not written; no nested-group hierarchy support yet.
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
	}, "filled", groupFill, "members_per_group", groupCap)
	if err != nil {
		return groupIDs, err
	}

	return groupIDs, nil
}

// validateLogins logs in as each of the loginUsers seeded users and confirms the
// token resolves to the expected entity. Concurrent and collect-all: the login
// pool is small (capped at login_users), so verifying every user is cheap.
func (i *Identity) validateLogins(client *api.Client, entityIDs []string) error {
	mountPath := userpassMountPath(i.runID)

	return runPhase(i.logger, "login resolution validation", i.loginUsers, func(idx int) error {
		name := objectName(i.mountName, "entity", i.runID, idx)
		return validateLogin(client, mountPath, name, entityIDs[idx])
	})
}
