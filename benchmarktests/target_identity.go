// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

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

	identityWorkloadPopulate  = "populate"
	identityWorkloadLogin     = "login"
	identityWorkloadGroupRead = "group_read"

	identityNoWorkloadPath = "/v1/sys/health"

	// Serial is faster against real Vault: the identity store serializes writes at the
	// storage layer, so goroutine overhead exceeds any parallelism benefit.
	// TODO: re-evaluate against integrated-storage clusters; if serial holds, remove this
	// constant and inline 1 directly in runConcurrent.
	identityConcurrency = 1

	identityProgressDivisions = 5
)

func init() {
	TestList[IdentityTestType] = func() BenchmarkBuilder { return &Identity{} }
}

type Identity struct {
	pathPrefix string
	header     http.Header
	config     *IdentityConfig
	mountName  string
	runID      string // per-run UUID; seeds every object name so each run is isolated

	method      string
	loginBody   []byte
	loginUsers  int      // min(login_users, alias_count, entity_count)
	loginPrefix string   // precomputed "mountName-entity-runID-"; avoids per-tick string allocs in Target
	groupIDs    []string // live ids for group_read; removing that workload simplifies this + Cleanup

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

// GroupConfig controls member assignment for the group_count groups:
// omit or preset="balanced" spreads entities evenly; "empty" fills nothing;
// "full" puts all entities in every group; count+size fills only count groups.
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

	if c.EntityCount <= 0 {
		return fmt.Errorf("entity_count must be greater than 0")
	}

	// Capped at alias_count (a user needs an alias) and entity_count (validateLogins indexes by entity).
	// TODO: revisit this clamp once aliases block lands (alias_count may exceed entity_count by design).
	i.loginUsers = min(c.LoginUsers, c.AliasCount, c.EntityCount)

	// TODO: guard alias_count/group_count/login_users for non-negative values.
	// TODO: each new workload touches three switches (here, Target, configureAttack); bundle if this grows.
	switch c.Workload {
	case identityWorkloadPopulate:
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

func (i *Identity) Target(client *api.Client) vegeta.Target {
	t := vegeta.Target{
		Method: i.method,
		URL:    client.Address() + i.pathPrefix,
		Header: i.header,
	}

	switch i.config.Workload {
	case identityWorkloadLogin:
		t.URL += "/login/" + i.loginPrefix + strconv.Itoa(rand.Intn(i.loginUsers))
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
	// identity is a built-in path; RandomMounts is ignored and the runID already isolates each run.
	i.logger = targetLogger.Named(IdentityTestType)

	runID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate run id: %w", err)
	}

	result := &Identity{
		config:      i.config,
		logger:      i.logger,
		mountName:   mountName,
		runID:       runID,
		loginUsers:  i.loginUsers,
		loginPrefix: mountName + "-entity-" + runID + "-",
	}

	// Accessor is the one value that can't be derived later; aliases bind by accessor, not path.
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

func (i *Identity) createEntities(client *api.Client, accessor string) ([]string, error) {
	total := i.config.EntityCount
	mountPath := userpassMountPath(i.runID)

	// Sized to what later steps actually need: full slice when groups read any entity,
	// login pool only when only validation reads them.
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

func (i *Identity) validateLogins(client *api.Client, entityIDs []string) error {
	mountPath := userpassMountPath(i.runID)

	return runPhase(i.logger, "login resolution validation", i.loginUsers, func(idx int) error {
		name := objectName(i.mountName, "entity", i.runID, idx)
		return validateLogin(client, mountPath, name, entityIDs[idx])
	})
}
