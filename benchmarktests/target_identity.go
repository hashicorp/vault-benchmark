// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// Identity benchmarks Vault's identity store: setup seeds entities (with optional
// aliases, userpass users, and groups), then the attack drives the selected
// workload. See docs/tests/identity.md for the config surface and rationale.
//
// Refactor roadmap (phases 1-3 landed; remaining work):
//   4. Behavior: the login attack pool is login_users against the large store.
//      A login with no matching alias auto-provisions a phantom entity, so
//      login_users stays a bounded subset of aliases -- the
//      min(login_users, alias_count) clamp in ParseConfig enforces this today.
//   5. Feature (separate PR): alias bloat via an `aliases` allocation block (like
//      `groups`) that fans an entity across multiple userpass mounts, the only
//      way past one alias/entity per mount.
//   6. Concurrency: this branch sits atop the concurrency branch (a work-first
//      PR); revisit and refine that merged implementation once it lands.

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

	// Attack-phase workload modes selected via the workload config field.
	identityWorkloadPopulate  = "populate"
	identityWorkloadLogin     = "login"
	identityWorkloadGroupRead = "group_read"

	// No-op attack target used by the populate workload.
	identityNoWorkloadPath = "/v1/sys/health"

	// Parallel workers used for entity/group creation, validation, and cleanup.
	identityConcurrency = 10

	// How often (in entities) to log creation progress during setup.
	identityProgressInterval = 1000
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityTestType] = func() BenchmarkBuilder { return &Identity{} }
}

// Identity seeds identity objects during setup and drives the workload attack.
type Identity struct {
	pathPrefix    string
	header        http.Header
	config        *IdentityConfig
	groupIDs      []string
	entityIDs     []string
	userpassMount string
	logger        hclog.Logger

	// Resolved in ParseConfig: how many groups get members and how many each,
	// plus the effective login-user pool (capped at alias_count).
	groupFilled int
	groupSize   int
	loginUsers  int

	method       string
	loginReqBody []byte
	mountName    string
	runID        string
	ownsMount    bool
}

type IdentityConfig struct {
	Workload    string       `hcl:"workload,optional"`
	EntityCount int          `hcl:"entity_count,optional"`
	GroupCount  int          `hcl:"group_count,optional"`
	AliasCount  int          `hcl:"alias_count,optional"`
	LoginUsers  int          `hcl:"login_users,optional"`
	Groups      *GroupConfig `hcl:"groups,block"`

	// TODO(future): aliases -- an allocation block (like groups) that fans entities
	// across multiple userpass mounts for >1 alias/entity (roadmap phase 5).
	// TODO(future): policies -- optional policy attach (mirror userpass token_policies).
}

// GroupConfig shapes how the group_count groups are filled: omit for an even
// split, or set a preset, or count+size for a partial allocation.
type GroupConfig struct {
	Preset string `hcl:"preset,optional"` // even (default) | empty | max
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
			GroupCount:  0,
			AliasCount:  0,
			LoginUsers:  100,
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
	if c.GroupCount < 0 {
		return fmt.Errorf("group_count cannot be negative")
	}
	if c.AliasCount < 0 {
		return fmt.Errorf("alias_count cannot be negative")
	}
	if c.AliasCount > c.EntityCount {
		// One alias per entity on a single mount (1:1); more needs extra mounts.
		return fmt.Errorf("alias_count (%d) cannot exceed entity_count (%d)", c.AliasCount, c.EntityCount)
	}
	if c.LoginUsers < 0 {
		return fmt.Errorf("login_users cannot be negative")
	}

	filled, size, err := resolveGroups(c.Groups, c.GroupCount, c.EntityCount)
	if err != nil {
		return err
	}
	i.groupFilled, i.groupSize = filled, size

	// A login user needs an alias to resolve, so the pool is capped at alias_count.
	i.loginUsers = min(c.LoginUsers, c.AliasCount)

	// Each workload has prerequisites that must be created during setup.
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

	randomMounts := topLevelConfig != nil && topLevelConfig.RandomMounts
	needMount := i.config.AliasCount > 0 || i.loginUsers > 0
	authLinker, err := newIdentityLinker(client, identityLinkerConfig{
		NeedsMount:   needMount,
		RandomMounts: randomMounts,
	})
	if err != nil {
		return nil, err
	}

	result := &Identity{
		config:        i.config,
		logger:        i.logger,
		mountName:     mountName,
		runID:         runID,
		userpassMount: authLinker.mountPath,
		ownsMount:     needMount && randomMounts,
		groupFilled:   i.groupFilled,
		groupSize:     i.groupSize,
		loginUsers:    i.loginUsers,
	}

	result.entityIDs, err = i.createEntities(client, mountName, runID, authLinker)
	if err != nil {
		return nil, err
	}

	if i.config.GroupCount > 0 {
		result.groupIDs, err = i.createGroups(client, mountName, runID, result.entityIDs)
		if err != nil {
			return nil, err
		}
	}

	if i.loginUsers > 0 {
		if err := i.validateLinks(client, mountName, runID, authLinker, result.entityIDs); err != nil {
			return nil, err
		}
	}

	result.method, result.pathPrefix, result.loginReqBody, err = configureAttack(i.config, authLinker)
	if err != nil {
		return nil, err
	}
	result.header = generateHeader(client)

	return result, nil
}

// createEntities creates EntityCount entities concurrently, giving the first
// AliasCount an entity alias and the first loginUsers a real userpass user
// (loginUsers <= alias_count, so every user's entity is also aliased). Each id
// is stored at its 1-based index so the result stays ordered without a mutex.
func (i *Identity) createEntities(client *api.Client, mountName, runID string, authLinker *identityLinker) ([]string, error) {
	start := time.Now()
	total := i.config.EntityCount
	i.logger.Info("entity population start", "total", total,
		"aliases", i.config.AliasCount, "login_users", i.loginUsers,
		"concurrency", identityConcurrency)

	entityIDs := make([]string, total)

	jobs := make(chan int, identityConcurrency)
	errs := make(chan error, total)
	var done atomic.Int64

	var wg sync.WaitGroup
	for range identityConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				name := entityName(mountName, runID, idx)

				resp, err := client.Logical().Write("identity/entity", map[string]any{
					"name": name,
				})
				if err != nil {
					errs <- fmt.Errorf("error creating identity entity %q: %w", name, err)
					continue
				}

				id, err := identityIDFromResponse(resp)
				if err != nil {
					errs <- fmt.Errorf("error reading identity entity id for %q: %w", name, err)
					continue
				}

				entityIDs[idx-1] = id

				createAlias := idx <= i.config.AliasCount
				createUser := idx <= i.loginUsers
				if err := authLinker.linkEntity(client, name, id, createAlias, createUser); err != nil {
					errs <- err
					continue
				}

				n := done.Add(1)
				if n%int64(identityProgressInterval) == 0 || int(n) == total {
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
// groupFilled groups each get groupSize members drawn deterministically from the
// created entities; any remaining groups are empty (per the groups allocation).
func (i *Identity) createGroups(client *api.Client, mountName, runID string, entityIDs []string) ([]string, error) {
	start := time.Now()
	total := i.config.GroupCount
	i.logger.Info("group population start", "total", total, "filled", i.groupFilled,
		"size", i.groupSize, "concurrency", identityConcurrency)

	groupIDs := make([]string, total)

	jobs := make(chan int, identityConcurrency)
	errs := make(chan error, total)

	var wg sync.WaitGroup
	for range identityConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				groupName := mountName + "-group-" + runID + "-" + strconv.Itoa(idx)
				var members []string
				if idx < i.groupFilled {
					members = selectGroupMembers(entityIDs, idx, i.groupSize)
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

				id, err := identityIDFromResponse(resp)
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

// validateLinks logs in as each of the loginUsers seeded users and confirms the
// token resolves to the expected entity. Concurrent; the first failure cancels
// the rest.
func (i *Identity) validateLinks(client *api.Client, mountName, runID string, authLinker *identityLinker, entityIDs []string) error {
	start := time.Now()
	total := i.loginUsers
	i.logger.Info("login resolution validation start", "users", total, "concurrency", identityConcurrency)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan int, identityConcurrency)
	errs := make(chan error, total)

	var wg sync.WaitGroup
	for w := 0; w < identityConcurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				name := entityName(mountName, runID, idx)
				if err := authLinker.validateLogin(client, name, entityIDs[idx-1]); err != nil {
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
		t.Body = i.loginReqBody
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
	i.logger.Info("cleanup start", "groups", len(i.groupIDs), "entities", len(i.entityIDs),
		"concurrency", identityConcurrency)

	var allErrs []error

	if err := deleteIDs(client, "identity/group/id/", i.groupIDs); err != nil {
		allErrs = append(allErrs, err)
	}

	// Deleting an entity removes its aliases, so aliases need no separate cleanup.
	if err := deleteIDs(client, "identity/entity/id/", i.entityIDs); err != nil {
		allErrs = append(allErrs, err)
	}

	// Disabling the run-scoped mount drops all its users in one call.
	if i.ownsMount {
		if err := client.Sys().DisableAuth(i.userpassMount); err != nil {
			allErrs = append(allErrs, fmt.Errorf("error disabling userpass mount %q: %v", i.userpassMount, err))
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
