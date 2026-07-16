// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// TODO(refactor-pr): identity target refactor checklist. Do the mechanical
// renames first (reviewable as a pure rename), then structural cleanup, then the
// config reframe. None of this changes current behavior.
//
// 1. Renames
//    [x] target/type/registry key: identity_group_read -> identity
//    [x] helper file: identity_auth_link_helper.go -> identity_linker.go (+ _test.go)
//    [x] helper types: identityAuthLinkHelper -> identityLinker,
//        identityAuthLinkConfig -> identityLinkerConfig
//    [x] helper funcs: newIdentityAuthLinkHelper -> newIdentityLinker,
//        ensureUserpassMountAccessor -> ensureMount,
//        normalizeAuthMountPath -> normalizeMountPath
//    [x] resolve getter/field collision so fields can shorten:
//        mountPath()/password() vs userpassMountPath/userPassword
//    [x] put the primary struct before its Config; add a type doc comment
//
// 2. Structural cleanup
//    [x] fold cleanupCreatedIdentityResources into Cleanup (split only for rollback)
//    [x] hardcode "userpass" mount; drop UserpassMount + normalizeMountPath
//        (random_mounts already isolates the run)
//    [x] progress_interval -> internal constant
//
// 3. Config reframe: counts -> shape (sculpt the identity DB to stress the storage
//    packer; confirm intent w/ team). Target surface:
//        workload     : populate | login | group_read
//        entity_count : primary scale axis
//        groups       : "default|empty|max" OR { count, size }
//                       (empty=size 0, max=1 group all members, default=even split)
//        aliases      : "default|..." OR { count }  (0..entity_count; >entity_count
//                       bloat needs multiple mounts -> phase 5)
//        policies     : optional attach + customize (mirror userpass token_policies)
//        user_validation_set : fixed real (bcrypt) users, default 100 -- ONE set
//                       used as BOTH the login-resolution sample and the login
//                       attack pool (never per-entity)
//    [ ] add the shape knobs above
//    [ ] drop create_aliases (-> aliases), create_users + validation_samples
//        (-> user_validation_set)
//    [ ] derive createAliases/createUsers internally from the new knobs
//
// 4. Behavior
//    [ ] login attack spans only user_validation_set against the large store
//        (userpass-style: few users, big bloat); Target() picks from that set
//    [ ] guard the U>A footgun: a login with no matching alias auto-provisions a
//        phantom entity, so users must be a bounded subset of aliases
//
// 5. Feature-tier (separate PR, not the refactor)
//    [ ] alias bloat: aliases { count } > entity_count via multiple mounts
//    [ ] parallelize setup creation -- the mount is enabled once up front so only
//        the per-entity writes parallelize; watch entity-alias writes racing on
//        the same canonical_id
//
// Assumptions to keep explicit: shape modes target the packer; alias bloat is
// feature-tier; users never scale with entities; policies reuse userpass knobs.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
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

	// Default login-resolution validation sample; ~99% chance of catching
	// corruption of >=5% of mappings, independent of entity_count.
	identityValidationSamples = 100

	// How often (in entities) to log creation progress during setup.
	identityProgressInterval = 1000
)

func init() {
	// "Register" this test to the main test registry
	TestList[IdentityTestType] = func() BenchmarkBuilder { return &Identity{} }
}

// Identity seeds Vault identity objects (entities, optional groups and userpass
// links) during setup and drives the configured workload during the attack.
type Identity struct {
	pathPrefix    string
	header        http.Header
	config        *IdentityConfig
	groupIDs      []string
	entityIDs     []string
	userpassMount string
	logger        hclog.Logger

	method       string
	loginReqBody []byte
	mountName    string
	runID        string
	ownsMount    bool
}

type IdentityConfig struct {
	EntityCount       int  `hcl:"entity_count,optional"`
	GroupCount        int  `hcl:"group_count,optional"`
	GroupSize         int  `hcl:"group_size,optional"`
	CreateAliases     bool `hcl:"create_aliases,optional"`
	ValidationSamples int  `hcl:"validation_samples,optional"`
	Concurrency       int  `hcl:"concurrency,optional"`

	Workload    string `hcl:"workload,optional"`
	CreateUsers bool   `hcl:"create_users,optional"`
}

func (i *Identity) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityConfig `hcl:"config,block"`
	}{
		Config: &IdentityConfig{
			EntityCount:       1000,
			GroupCount:        0,
			GroupSize:         10,
			CreateAliases:     false,
			ValidationSamples: identityValidationSamples,
			Concurrency:       10,
			Workload:          identityWorkloadPopulate,
			CreateUsers:       false,
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
	if i.config.ValidationSamples <= 0 {
		return fmt.Errorf("validation_samples must be greater than 0")
	}
	if i.config.Concurrency < 1 {
		return fmt.Errorf("concurrency must be greater than 0")
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

	// Each workload has prerequisites that must be created during setup.
	switch i.config.Workload {
	case identityWorkloadPopulate:
		// Seed only: no prerequisites.
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
			i.config.Workload, identityWorkloadPopulate, identityWorkloadLogin, identityWorkloadGroupRead)
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
	authLinker, err := newIdentityLinker(client, identityLinkerConfig{
		CreateAliases: i.config.CreateAliases,
		CreateUsers:   i.config.CreateUsers,
		RandomMounts:  randomMounts,
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
		ownsMount:     (i.config.CreateAliases || i.config.CreateUsers) && randomMounts,
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

	if i.config.CreateAliases {
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

// createEntities creates EntityCount entities (linking each to userpass as
// configured) concurrently, storing each id at its 1-based index so the result
// stays ordered without a mutex.
func (i *Identity) createEntities(client *api.Client, mountName, runID string, authLinker *identityLinker) ([]string, error) {
	start := time.Now()
	total := i.config.EntityCount
	i.logger.Info("entity population start", "total", total,
		"create_aliases", i.config.CreateAliases, "create_users", i.config.CreateUsers,
		"concurrency", i.config.Concurrency)

	entityIDs := make([]string, total)

	jobs := make(chan int, i.config.Concurrency)
	errs := make(chan error, total)
	var done atomic.Int64

	var wg sync.WaitGroup
	for w := 0; w < i.config.Concurrency; w++ {
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

				if err := authLinker.linkEntity(client, name, id); err != nil {
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

// createGroups creates GroupCount internal groups concurrently, each with
// GroupSize members drawn deterministically from the created entities.
func (i *Identity) createGroups(client *api.Client, mountName, runID string, entityIDs []string) ([]string, error) {
	start := time.Now()
	total := i.config.GroupCount
	i.logger.Info("group population start", "total", total, "group_size", i.config.GroupSize,
		"concurrency", i.config.Concurrency)

	groupIDs := make([]string, total)

	jobs := make(chan int, i.config.Concurrency)
	errs := make(chan error, total)

	var wg sync.WaitGroup
	for w := 0; w < i.config.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				groupName := mountName + "-group-" + runID + "-" + strconv.Itoa(idx)
				members := selectGroupMembers(entityIDs, idx, i.config.GroupSize)

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

// validateLinks logs in a random sample of users and confirms each token
// resolves to the expected entity. Concurrent; the first failure cancels the rest.
func (i *Identity) validateLinks(client *api.Client, mountName, runID string, authLinker *identityLinker, entityIDs []string) error {
	start := time.Now()
	sampleCount := min(i.config.ValidationSamples, i.config.EntityCount)
	i.logger.Info("login resolution validation start", "samples", sampleCount, "entities", i.config.EntityCount,
		"concurrency", i.config.Concurrency)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	indices := sampleIndices(i.config.EntityCount, sampleCount)
	jobs := make(chan int, i.config.Concurrency)
	errs := make(chan error, len(indices))

	var wg sync.WaitGroup
	for w := 0; w < i.config.Concurrency; w++ {
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

	for _, idx := range indices {
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

	i.logger.Info("login resolution validation complete", "samples", sampleCount, "elapsed", time.Since(start).String())
	return nil
}

// configureAttack returns the method, path prefix, and optional login body for
// the selected workload (populate falls back to a health check).
func configureAttack(cfg *IdentityConfig, authLinker *identityLinker) (method, pathPrefix string, loginReqBody []byte, err error) {
	switch cfg.Workload {
	case identityWorkloadLogin:
		body, marshalErr := json.Marshal(map[string]string{"password": authLinker.password})
		if marshalErr != nil {
			return "", "", nil, fmt.Errorf("error encoding login request body: %w", marshalErr)
		}
		return http.MethodPost,
			"/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath)),
			body, nil
	case identityWorkloadGroupRead:
		return http.MethodGet, "/v1/identity/group/id/", nil, nil
	default: // identityWorkloadPopulate
		return http.MethodGet, identityNoWorkloadPath, nil, nil
	}
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
		user := entityName(i.mountName, i.runID, rand.Intn(i.config.EntityCount)+1)
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
		"concurrency", i.config.Concurrency)

	var allErrs []error

	if err := i.deleteIDs(client, "identity/group/id/", i.groupIDs); err != nil {
		allErrs = append(allErrs, err)
	}

	// Deleting an entity removes its aliases, so aliases need no separate cleanup.
	if err := i.deleteIDs(client, "identity/entity/id/", i.entityIDs); err != nil {
		allErrs = append(allErrs, err)
	}

	// Disabling the run-scoped mount drops all its users in one call.
	if i.ownsMount && i.userpassMount != "" {
		if err := client.Sys().DisableAuth(i.userpassMount); err != nil {
			allErrs = append(allErrs, fmt.Errorf("error disabling userpass mount %q: %v", i.userpassMount, err))
		}
	}

	i.logger.Info("cleanup complete", "elapsed", time.Since(start).String())
	return errors.Join(allErrs...)
}

// deleteIDs deletes each id under pathPrefix concurrently.
func (i *Identity) deleteIDs(client *api.Client, pathPrefix string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	jobs := make(chan string, i.config.Concurrency)
	errs := make(chan error, len(ids))

	var wg sync.WaitGroup
	for w := 0; w < i.config.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				if _, err := client.Logical().Delete(pathPrefix + id); err != nil {
					errs <- fmt.Errorf("error deleting %s%s: %v", pathPrefix, id, err)
				}
			}
		}()
	}

	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	close(errs)

	var allErrs []error
	for err := range errs {
		allErrs = append(allErrs, err)
	}
	return errors.Join(allErrs...)
}

func (i *Identity) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     i.method,
		pathPrefix: i.pathPrefix,
	}
}

func (i *Identity) Flags(fs *flag.FlagSet) {}
