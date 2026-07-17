// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// Identity benchmarks Vault's identity store: setup seeds entities (with optional
// aliases, userpass users, and groups), then the attack drives the selected
// workload. See docs/tests/identity.md for the config surface and rationale.
//
// TODO(phase 6): this branch sits atop the concurrency branch (a work-first PR);
// revisit and refine that merged concurrency implementation once it lands.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
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
	password   string   // userpass password for login bodies
	loginUsers int      // resolved login pool, min(login_users, alias_count)
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

	// A login user needs an alias to resolve, so the pool is capped at alias_count.
	i.loginUsers = min(c.LoginUsers, c.AliasCount)

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
	// identity is a built-in path, so this target manages no secret mount.
	i.logger = targetLogger.Named(IdentityTestType)

	runID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate run id: %v", err)
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
	result.header = generateHeader(client)

	return result, nil
}

// createEntities creates EntityCount entities concurrently: the first AliasCount
// get an alias and the first loginUsers also get a userpass user (loginUsers <=
// alias_count, so every user is aliased). Ids are collected only when a later step
// reads them (groups or validation), each at its 1-based index so the slice stays
// ordered without a lock.
func (i *Identity) createEntities(client *api.Client, accessor string) ([]string, error) {
	start := time.Now()
	total := i.config.EntityCount
	i.logger.Info("entity population start", "total", total,
		"aliases", i.config.AliasCount, "login_users", i.loginUsers,
		"concurrency", identityConcurrency)

	// Computed once; used only by entities that get a user.
	mountPath := userpassMountPath(i.runID)

	// Skip the entity_count-sized slice unless groups or validation read the ids.
	var entityIDs []string
	if i.config.GroupCount > 0 || i.loginUsers > 0 {
		entityIDs = make([]string, total)
	}

	progressInterval := ceilDiv(total, identityProgressDivisions)
	jobs := make(chan int, identityConcurrency)
	// TODO(phase 6): sized to total so no worker blocks on send, but that reserves
	// an entity_count-sized buffer even on success; revisit in the concurrency review.
	errs := make(chan error, total)
	var done atomic.Int64

	var wg sync.WaitGroup
	for range identityConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				name := entityName(i.mountName, i.runID, idx)

				resp, err := client.Logical().Write("identity/entity", map[string]any{
					"name": name,
				})
				if err != nil {
					errs <- fmt.Errorf("error creating identity entity %q: %w", name, err)
					continue
				}

				id, err := idFromResponse(resp)
				if err != nil {
					errs <- fmt.Errorf("error reading identity entity id for %q: %w", name, err)
					continue
				}

				if entityIDs != nil {
					entityIDs[idx-1] = id
				}

				if idx <= i.config.AliasCount {
					if err := addEntityAlias(client, accessor, name, id); err != nil {
						errs <- err
						continue
					}
				}
				if idx <= i.loginUsers {
					if err := addUserpassUser(client, mountPath, name, i.password); err != nil {
						errs <- err
						continue
					}
				}

				n := done.Add(1)
				if n%int64(progressInterval) == 0 || int(n) == total {
					i.logger.Info("entity population", "progress", fmt.Sprintf("%d/%d", n, total))
				}
			}
		}()
	}

	for idx := 1; idx <= total; idx++ {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(errs)

	var allErrs []error
	for err := range errs {
		allErrs = append(allErrs, err)
	}
	if err := errors.Join(allErrs...); err != nil {
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
		"members_per_group", groupCap, "concurrency", identityConcurrency)

	groupIDs := make([]string, total)

	jobs := make(chan int, identityConcurrency)
	errs := make(chan error, total)

	var wg sync.WaitGroup
	for range identityConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				groupName := i.mountName + "-group-" + i.runID + "-" + strconv.Itoa(idx)
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
					errs <- fmt.Errorf("error creating identity group %q: %w", groupName, err)
					continue
				}

				id, err := idFromResponse(resp)
				if err != nil {
					errs <- fmt.Errorf("error reading identity group id for %q: %w", groupName, err)
					continue
				}

				groupIDs[idx] = id
			}
		}()
	}

	for idx := range total {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(errs)

	var allErrs []error
	for err := range errs {
		allErrs = append(allErrs, err)
	}
	if err := errors.Join(allErrs...); err != nil {
		return groupIDs, err
	}

	i.logger.Info("group population complete", "total", total, "elapsed", time.Since(start).String())
	return groupIDs, nil
}

// validateAliases logs in as each of the loginUsers seeded users and confirms the
// token resolves to the expected entity. Concurrent; the first failure cancels
// the rest.
func (i *Identity) validateAliases(client *api.Client, entityIDs []string) error {
	start := time.Now()
	total := i.loginUsers
	i.logger.Info("login resolution validation start", "users", total, "concurrency", identityConcurrency)

	mountPath := userpassMountPath(i.runID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan int, identityConcurrency)
	errs := make(chan error, total)

	var wg sync.WaitGroup
	for range identityConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				name := entityName(i.mountName, i.runID, idx)
				if err := validateLogin(client, mountPath, name, i.password, entityIDs[idx-1]); err != nil {
					errs <- err
					cancel()
					return
				}
			}
		}()
	}

	for idx := 1; idx <= total; idx++ {
		if ctx.Err() != nil {
			break
		}
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(errs)

	if err := <-errs; err != nil {
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
		user := entityName(i.mountName, i.runID, rand.Intn(i.loginUsers)+1)
		t.URL += "/login/" + user
		t.Body = fmt.Appendf(nil, `{"password": "%s"}`, i.password)
	case identityWorkloadGroupRead:
		if len(i.groupIDs) > 0 {
			t.URL += i.groupIDs[rand.Intn(len(i.groupIDs))]
		}
	}

	return t
}

func (i *Identity) Cleanup(client *api.Client) error {
	if i.config.Workload == identityWorkloadPopulate {
		i.logger.Info("populate workload; leaving seeded identity objects in place")
		return nil
	}

	start := time.Now()
	i.logger.Info("cleanup start", "groups", len(i.groupIDs), "entities", i.config.EntityCount,
		"concurrency", identityConcurrency)

	var allErrs []error

	// Groups are already held by id (attack state), so delete by id. Entities
	// aren't kept, so re-derive their names and delete by name (which also drops
	// each entity's aliases).
	if err := deleteEach(client, "identity/group/id/", i.groupIDs); err != nil {
		allErrs = append(allErrs, err)
	}

	entityNames := make([]string, i.config.EntityCount)
	for idx := 1; idx <= i.config.EntityCount; idx++ {
		entityNames[idx-1] = entityName(i.mountName, i.runID, idx)
	}
	if err := deleteEach(client, "identity/entity/name/", entityNames); err != nil {
		allErrs = append(allErrs, err)
	}

	// Disabling the run-scoped userpass mount drops all its users in one call; its
	// path is derived from the run id.
	if i.config.AliasCount > 0 {
		mountPath := userpassMountPath(i.runID)
		if err := client.Sys().DisableAuth(mountPath); err != nil {
			allErrs = append(allErrs, fmt.Errorf("error disabling userpass mount %q: %v", mountPath, err))
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
