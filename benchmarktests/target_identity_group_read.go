// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// TODO(refactor-pr):
//   - rename target/type/registry key from identity_group_read to identity
//   - rename cleanupCreatedIdentityResources -> cleanupIdentityResources
//
// TODO(feature): richer user<->entity mapping — support N:1 links and alias
//   bloating (multiple users/aliases per entity) so load can be weighted and
//   shaped independently of entity_count.
//   - decouple user count from entity_count (bcrypt cost is pinned to entity_count
//     whenever create_users is set)

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
	// "Register" this test to the main test registry. The former
	// identity_population target is merged in here, so only identity_group_read
	// is registered now.
	TestList[IdentityGroupReadTestType] = func() BenchmarkBuilder { return &IdentityGroupRead{} }
}

// IdentityGroupRead is the consolidated identity target (group_read + login/population).
type IdentityGroupRead struct {
	pathPrefix    string
	header        http.Header
	config        *IdentityGroupReadConfig
	groupIDs      []string
	entityIDs     []string
	userpassMount string
	logger        hclog.Logger

	// Added for the merged login/population workload.
	method     string
	loginBody  []byte
	mountName  string
	runID      string
	ownsMount  bool
	authLinker *identityAuthLinkHelper
}

type IdentityGroupReadConfig struct {
	EntityCount       int    `hcl:"entity_count,optional"`
	GroupCount        int    `hcl:"group_count,optional"`
	GroupSize         int    `hcl:"group_size,optional"`
	CreateAliases     bool   `hcl:"create_aliases,optional"`
	UserpassMount     string `hcl:"userpass_mount,optional"`
	ValidationSamples int    `hcl:"validation_samples,optional"`
	Concurrency       int    `hcl:"concurrency,optional"`

	// Added for the merged login/population workload.
	Workload         string `hcl:"workload,optional"`
	CreateUsers      bool   `hcl:"create_users,optional"`
	NamePrefix       string `hcl:"name_prefix,optional"`
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
			Workload:          identityWorkloadNone,
			CreateUsers:       false,
			NamePrefix:        "entity",
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
	if i.config.NamePrefix == "" {
		return fmt.Errorf("name_prefix cannot be empty")
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
	case identityWorkloadNone:
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
			i.config.Workload, identityWorkloadNone, identityWorkloadLogin, identityWorkloadGroupRead)
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

	entityIDs := make([]string, 0, i.config.EntityCount)
	groupIDs := make([]string, 0, i.config.GroupCount)

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

	if err := i.createEntities(client, mountName, runID, authLinker, entityIDs); err != nil {
		_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, ownsMount, userpassMount)
		return nil, err
	}
	entityIDs = i.entityIDs

	if i.config.GroupCount > 0 {
		if err := i.createGroups(client, mountName, runID, entityIDs, groupIDs); err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, ownsMount, userpassMount)
			return nil, err
		}
		groupIDs = i.groupIDs
	}

	if i.config.CreateAliases {
		if err := i.validateLinks(client, mountName, runID, authLinker); err != nil {
			_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, ownsMount, userpassMount)
			return nil, err
		}
	}

	header := generateHeader(client)
	method, pathPrefix, loginBody, err := configureAttack(i.config, authLinker)
	if err != nil {
		_ = i.cleanupCreatedIdentityResources(client, groupIDs, entityIDs, ownsMount, userpassMount)
		return nil, err
	}

	return &IdentityGroupRead{
		pathPrefix:    pathPrefix,
		header:        header,
		config:        i.config,
		groupIDs:      groupIDs,
		entityIDs:     entityIDs,
		method:        method,
		loginBody:     loginBody,
		mountName:     mountName,
		runID:         runID,
		userpassMount: userpassMount,
		ownsMount:     ownsMount,
		authLinker:    authLinker,
		logger:        i.logger,
	}, nil
}

// createEntities creates EntityCount entities and links each to userpass as
// configured, populating i.entityIDs.
func (i *IdentityGroupRead) createEntities(client *api.Client, mountName, runID string, authLinker *identityAuthLinkHelper, _ []string) error {
	start := time.Now()
	i.logger.Info("entity population start", "total", i.config.EntityCount,
		"create_aliases", i.config.CreateAliases, "create_users", i.config.CreateUsers,
		"concurrency", i.config.Concurrency)

	total := i.config.EntityCount
	i.entityIDs = make([]string, total)

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

				i.entityIDs[idx-1] = id

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
		return err
	}

	i.logger.Info("entity population complete", "total", total, "elapsed", time.Since(start).String())
	return nil
}

// createGroups creates GroupCount internal groups, each populated with GroupSize
// members drawn deterministically from the created entities.
func (i *IdentityGroupRead) createGroups(client *api.Client, mountName, runID string, entityIDs, _ []string) error {
	total := i.config.GroupCount
	i.groupIDs = make([]string, total)

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

				i.groupIDs[idx] = id
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
		return err
	}

	i.logger.Info("group population complete", "total", total)
	return nil
}

// validateLinks verifies a random sample of alias->entity mappings by logging in
// and confirming the token resolves to the expected entity.
func (i *IdentityGroupRead) validateLinks(client *api.Client, mountName, runID string, authLinker *identityAuthLinkHelper) error {
	sampleCount := min(i.config.ValidationSamples, i.config.EntityCount)
	for _, idx := range sampleIndices(i.config.EntityCount, sampleCount) {
		name := entityName(mountName, runID, idx)
		if err := authLinker.validateLogin(client, name, i.entityIDs[idx-1]); err != nil {
			return err
		}
	}
	i.logger.Info("login resolution validated", "samples", sampleCount, "entities", i.config.EntityCount)
	return nil
}

// configureAttack returns the method, pathPrefix, and optional loginBody for the
// selected workload: group_read hits GET /identity/group/id/, login POSTs to the
// userpass mount, and none falls back to a cheap health check.
func configureAttack(cfg *IdentityGroupReadConfig, authLinker *identityAuthLinkHelper) (method, pathPrefix string, loginBody []byte, err error) {
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
	default: // identityWorkloadNone
		return http.MethodGet, identityNoWorkloadPath, nil, nil
	}
}

// Target drives the configured workload: a login POST, a group read, or the
// no-workload health check.
func (i *IdentityGroupRead) Target(client *api.Client) vegeta.Target {
	switch i.config.Workload {
	case identityWorkloadLogin:
		user := entityName(i.mountName, i.runID, rand.Intn(i.config.EntityCount)+1)
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

func (i *IdentityGroupRead) Cleanup(client *api.Client) error {
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

// entityName derives a run-unique, index-addressable entity name of the form
// mountName-entity-runID-idx.
func entityName(mountName, runID string, idx int) string {
	return mountName + "-entity-" + runID + "-" + strconv.Itoa(idx)
}

func selectGroupMembers(entityIDs []string, groupIndex int, groupSize int) []string {
	members := make([]string, 0, groupSize)
	start := (groupIndex * groupSize) % len(entityIDs)

	for offset := 0; offset < groupSize; offset++ {
		members = append(members, entityIDs[(start+offset)%len(entityIDs)])
	}

	return members
}
