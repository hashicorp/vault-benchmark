// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// TODO(refactor-pr): identity target refactor checklist. Do the mechanical
// renames first (reviewable as a pure rename), then structural cleanup, then the
// config reframe. None of this changes current behavior.
//
// 1. Renames
//    [ ] target/type/registry key: identity_group_read -> identity
//    [ ] helper file: identity_auth_link_helper.go -> identity_linker.go (+ _test.go)
//    [ ] helper types: identityAuthLinkHelper -> identityLinker,
//        identityAuthLinkConfig -> identityLinkerConfig
//    [ ] helper funcs: newIdentityAuthLinkHelper -> newIdentityLinker,
//        ensureUserpassMountAccessor -> ensureMount,
//        normalizeAuthMountPath -> normalizeMountPath
//    [ ] resolve getter/field collision so fields can shorten:
//        mountPath()/password() vs userpassMountPath/userPassword
//    [ ] put the primary struct before its Config; add a type doc comment
//
// 2. Structural cleanup
//    [ ] fold cleanupCreatedIdentityResources into Cleanup (split only for rollback)
//    [ ] hardcode "userpass" mount; drop UserpassMount + normalizeAuthMountPath
//        (random_mounts already isolates the run)
//    [ ] progress_interval -> internal constant
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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
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
	IdentityGroupReadTestType = "identity_group_read"

	// Attack-phase workload modes selected via the workload config field.
	identityWorkloadPopulate  = "populate"
	identityWorkloadLogin     = "login"
	identityWorkloadGroupRead = "group_read"

	// No-op attack target used by the populate workload.
	identityNoWorkloadPath = "/v1/sys/health"

	// Default random-sample size for login-resolution validation. A sample of
	// 100 aliases gives a high probability (>99%) of detecting corruption
	// affecting 5% or more of mappings, independent of entity_count.
	identityValidationSamples = 100
)

func init() {
	TestList[IdentityGroupReadTestType] = func() BenchmarkBuilder { return &IdentityGroupRead{} }
}

// Identity Group Read Test Struct
type IdentityGroupRead struct {
	pathPrefix    string
	header        http.Header
	config        *IdentityGroupReadConfig
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

type IdentityGroupReadConfig struct {
	EntityCount       int    `hcl:"entity_count,optional"`
	GroupCount        int    `hcl:"group_count,optional"`
	GroupSize         int    `hcl:"group_size,optional"`
	CreateAliases     bool   `hcl:"create_aliases,optional"`
	UserpassMount     string `hcl:"userpass_mount,optional"`
	ValidationSamples int    `hcl:"validation_samples,optional"`
	Concurrency       int    `hcl:"concurrency,optional"`

	Workload         string `hcl:"workload,optional"`
	CreateUsers      bool   `hcl:"create_users,optional"`
	ProgressInterval int    `hcl:"progress_interval,optional"`
}

func (i *IdentityGroupRead) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *IdentityGroupReadConfig `hcl:"config,block"`
	}{
		Config: &IdentityGroupReadConfig{
			EntityCount:       1000,
			GroupCount:        0,
			GroupSize:         10,
			CreateAliases:     false,
			UserpassMount:     "userpass",
			ValidationSamples: identityValidationSamples,
			Concurrency:       10,
			Workload:          identityWorkloadPopulate,
			CreateUsers:       false,
			ProgressInterval:  1000,
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

	// Auth linking (aliases and/or users) needs a mount to attach to.
	if (i.config.CreateAliases || i.config.CreateUsers) && strings.TrimSpace(i.config.UserpassMount) == "" {
		return fmt.Errorf("userpass_mount cannot be empty when create_aliases or create_users is set")
	}

	// Each workload has prerequisites that must be created during setup.
	switch i.config.Workload {
	case identityWorkloadPopulate:
		// Seed only: no attack-phase prerequisites.
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

func (i *IdentityGroupRead) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	// identity is a built-in path, so this target manages no secret mount.
	i.logger = targetLogger.Named(IdentityGroupReadTestType)

	runID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate run id: %v", err)
	}

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

	userpassMount := authLinker.mountPath()
	ownsMount := (i.config.CreateAliases || i.config.CreateUsers) && randomMounts

	// Roll back any partially created identity resources unless setup succeeds.
	var entityIDs, groupIDs []string
	success := false
	defer func() {
		if !success {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, ownsMount, userpassMount)
		}
	}()

	entityIDs, err = i.createEntities(client, mountName, runID, authLinker)
	if err != nil {
		return nil, err
	}

	if i.config.GroupCount > 0 {
		groupIDs, err = i.createGroups(client, mountName, runID, entityIDs)
		if err != nil {
			return nil, err
		}
	}

	if i.config.CreateAliases {
		if err := i.validateLinks(client, mountName, runID, authLinker, entityIDs); err != nil {
			return nil, err
		}
	}

	method, pathPrefix, loginReqBody, err := configureAttack(i.config, authLinker)
	if err != nil {
		return nil, err
	}

	success = true
	return &IdentityGroupRead{
		pathPrefix:    pathPrefix,
		header:        generateHeader(client),
		config:        i.config,
		groupIDs:      groupIDs,
		entityIDs:     entityIDs,
		method:        method,
		loginReqBody:  loginReqBody,
		mountName:     mountName,
		runID:         runID,
		userpassMount: userpassMount,
		ownsMount:     ownsMount,
		logger:        i.logger,
	}, nil
}

// createEntities creates EntityCount entities and links each to userpass as
// configured. Workers run concurrently up to Concurrency, storing ids at their
// 1-based index so the slice is ordered without a mutex. Returns ids in creation
// order so the caller can roll them back on error.
func (i *IdentityGroupRead) createEntities(client *api.Client, mountName, runID string, authLinker *identityAuthLinkHelper) ([]string, error) {
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
				if n%int64(i.config.ProgressInterval) == 0 || int(n) == total {
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

// createGroups creates GroupCount internal groups, each populated with GroupSize
// members drawn deterministically from the created entities. Workers run
// concurrently up to Concurrency. Returns ids in creation order so the caller
// can roll them back on error.
func (i *IdentityGroupRead) createGroups(client *api.Client, mountName, runID string, entityIDs []string) ([]string, error) {
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

	for idx := 0; idx < total; idx++ {
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

// validateLinks verifies a random sample of alias->entity mappings by logging in
// and confirming the token resolves to the expected entity.
func (i *IdentityGroupRead) validateLinks(client *api.Client, mountName, runID string, authLinker *identityAuthLinkHelper, entityIDs []string) error {
	start := time.Now()
	sampleCount := min(i.config.ValidationSamples, i.config.EntityCount)
	i.logger.Info("login resolution validation start", "samples", sampleCount, "entities", i.config.EntityCount)

	for _, idx := range sampleIndices(i.config.EntityCount, sampleCount) {
		name := entityName(mountName, runID, idx)
		if err := authLinker.validateLogin(client, name, entityIDs[idx-1]); err != nil {
			return err
		}
	}

	i.logger.Info("login resolution validation complete", "samples", sampleCount, "elapsed", time.Since(start).String())
	return nil
}

// configureAttack returns the method, pathPrefix, and optional login request body
// for the selected workload: group_read hits GET /identity/group/id/, login POSTs
// to the userpass mount, and populate falls back to a cheap health check.
func configureAttack(cfg *IdentityGroupReadConfig, authLinker *identityAuthLinkHelper) (method, pathPrefix string, loginReqBody []byte, err error) {
	switch cfg.Workload {
	case identityWorkloadLogin:
		body, marshalErr := json.Marshal(map[string]string{"password": authLinker.password()})
		if marshalErr != nil {
			return "", "", nil, fmt.Errorf("error encoding login request body: %w", marshalErr)
		}
		return http.MethodPost,
			"/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath())),
			body, nil
	case identityWorkloadGroupRead:
		return http.MethodGet, "/v1/identity/group/id/", nil, nil
	default: // identityWorkloadPopulate
		return http.MethodGet, identityNoWorkloadPath, nil, nil
	}
}

// Target drives the configured workload: a login POST, a group read, or the
// no-workload health check. All variants share a base target and adjust only the
// URL (and body, for login).
func (i *IdentityGroupRead) Target(client *api.Client) vegeta.Target {
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

func (i *IdentityGroupRead) Cleanup(client *api.Client) error {
	if i.config.Workload == identityWorkloadPopulate {
		i.logger.Info("populate workload; leaving seeded identity objects in place")
		return nil
	}

	i.logger.Trace("cleaning up identity benchmark resources")
	return i.cleanupCreatedIdentityResources(client, i.groupIDs, i.entityIDs, i.ownsMount, i.userpassMount)
}

// cleanupCreatedIdentityResources deletes groups, entities, and, when this run
// owns the userpass mount, disables it to remove all linked and probe users.
func (i *IdentityGroupRead) cleanupCreatedIdentityResources(client *api.Client, groupIDs []string, entityIDs []string, ownsMount bool, userpassMount string) error {
	var firstErr error

	for _, groupID := range groupIDs {
		_, err := client.Logical().Delete("identity/group/id/" + groupID)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting identity group %q: %v", groupID, err)
		}
	}

	// Deleting an entity removes its aliases, so aliases need no separate cleanup.
	for _, entityID := range entityIDs {
		_, err := client.Logical().Delete("identity/entity/id/" + entityID)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error deleting identity entity %q: %v", entityID, err)
		}
	}

	// The run-scoped userpass mount holds every linked and probe user, so
	// disabling it removes them all in a single call.
	if ownsMount && userpassMount != "" {
		if err := client.Sys().DisableAuth(userpassMount); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("error disabling userpass mount %q: %v", userpassMount, err)
		}
	}

	return firstErr
}

func (i *IdentityGroupRead) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     i.method,
		pathPrefix: i.pathPrefix,
	}
}

func (i *IdentityGroupRead) Flags(fs *flag.FlagSet) {}
