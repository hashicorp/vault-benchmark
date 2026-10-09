// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// target_scim_groups.go implements four SCIM group workloads:
//
//   - group_create: POST /scim/v2/Groups with a fresh unique displayName each time.
//     Optional members_per_group controls how many SCIM-owned entity IDs appear in
//     each POST body (tests the "groups with many memberships" case).
//
//   - group_create_empty: POST /scim/v2/Groups with no members. Baseline for
//     comparing membership overhead against group_create.
//
//   - group_adopt: PUT /scim/v2/Groups/<id> with displayName matching a pre-seeded
//     unmanaged group. Setup seeds group_count groups via the admin identity API.
//     Note: group adoption uses PUT (not POST), targeting the group's Vault ID.
//
//   - group_list: GET /scim/v2/Groups with a round-robin selection of filter
//     expressions (including the bare, no-filter case).
//
// All four workloads share a single SCIM client per benchmark run
// (see scim_helper.go — scimAcquireSharedClient). This mirrors a real IdP:
// one Entra/Okta tenant has one credential, not one per operation type.

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	SCIMGroupsTestType = "scim_groups"

	scimGroupWorkloadCreate      = "group_create"
	scimGroupWorkloadCreateEmpty = "group_create_empty"
	scimGroupWorkloadAdopt       = "group_adopt"
	scimGroupWorkloadList        = "group_list"
)

func init() {
	TestList[SCIMGroupsTestType] = func() BenchmarkBuilder { return &SCIMGroups{} }
}

// SCIMGroups implements BenchmarkBuilder for SCIM group workloads.
type SCIMGroups struct {
	pathPrefix string
	header     http.Header
	logger     hclog.Logger

	// sc is the shared SCIM client; all workloads in a run share one client.
	sc        *scimSharedClient
	namespace string

	// group_create / group_create_empty: pool of unique displayNames.
	createGroupNames []string
	// group_create: pool of SCIM-owned entity IDs for membership bodies.
	scimEntityIDs []string

	// group_adopt: (vaultGroupID, displayName) pairs for the PUT request.
	adoptGroupIDs   []string
	adoptGroupNames []string

	// group_list: pre-built URL strings.
	listURLs []string

	atomicIdx int64

	config *SCIMGroupsConfig
}

// SCIMGroupsConfig holds all HCL-configurable parameters for the SCIM groups target.
type SCIMGroupsConfig struct {
	// Workload selects which group workload to run.
	// One of: "group_create" | "group_create_empty" | "group_adopt" | "group_list"
	Workload string `hcl:"workload,optional"`

	// GroupCount is:
	//   group_create / group_create_empty: size of the unique-name pool
	//   group_adopt: number of pre-seeded unmanaged groups to create
	//   group_list:  ignored
	GroupCount int `hcl:"group_count,optional"`

	// MembersPerGroup is the number of SCIM-owned entity IDs to include in each
	// group_create POST body. 0 = no members (same as group_create_empty).
	MembersPerGroup int `hcl:"members_per_group,optional"`

	// UserSeedCount is the number of SCIM-owned users to create during setup for
	// use as group members. Only meaningful when MembersPerGroup > 0.
	// Defaults to MembersPerGroup when not set.
	UserSeedCount int `hcl:"user_seed_count,optional"`

	// Filters is the list of SCIM filter query-strings cycled for group_list.
	// An empty string means "no filter". Defaults to [""] when omitted.
	// A filter may contain the token $SEED_GROUPNAME, which is substituted with
	// the displayName of a pre-seeded group (see SeedGroupCount) so a point-lookup
	// filter is guaranteed to match real data.
	Filters []string `hcl:"filters,optional"`

	// SeedGroupCount pre-seeds this many SCIM-owned groups during setup, purely as
	// queryable data for group_list filter tests. Ignored for other workloads.
	SeedGroupCount int `hcl:"seed_group_count,optional"`

	// SeedConcurrency is the number of parallel workers used for setup seeding
	// (group_adopt groups, group member users, group_list seed groups) and for
	// the teardown sweep. Defaults to 16. It does not affect the measured attack phase.
	SeedConcurrency int `hcl:"seed_concurrency,optional"`
}

func (s *SCIMGroups) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *SCIMGroupsConfig `hcl:"config,block"`
	}{
		Config: &SCIMGroupsConfig{
			Workload:        scimGroupWorkloadCreate,
			GroupCount:      100,
			MembersPerGroup: 0,
			Filters:         []string{""},
			SeedConcurrency: scimDefaultSeedConcurrency,
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding scim_groups config: %v", diags)
	}

	c := testConfig.Config
	s.config = c

	if c.SeedConcurrency < 1 {
		return fmt.Errorf("scim_groups: seed_concurrency must be >= 1")
	}

	switch c.Workload {
	case scimGroupWorkloadCreate, scimGroupWorkloadCreateEmpty, scimGroupWorkloadAdopt:
		if c.GroupCount <= 0 {
			return fmt.Errorf("scim_groups: group_count must be > 0 for workload %q", c.Workload)
		}
	case scimGroupWorkloadList:
		if len(c.Filters) == 0 {
			c.Filters = []string{""}
		}
	default:
		return fmt.Errorf("scim_groups: invalid workload %q; must be one of %q, %q, %q, %q",
			c.Workload, scimGroupWorkloadCreate, scimGroupWorkloadCreateEmpty, scimGroupWorkloadAdopt, scimGroupWorkloadList)
	}

	if c.MembersPerGroup < 0 {
		return fmt.Errorf("scim_groups: members_per_group must be >= 0")
	}
	if c.UserSeedCount == 0 && c.MembersPerGroup > 0 {
		c.UserSeedCount = c.MembersPerGroup
	}
	if c.SeedGroupCount < 0 {
		return fmt.Errorf("scim_groups: seed_group_count must be >= 0")
	}

	return nil
}

func (s *SCIMGroups) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	s.logger = targetLogger.Named(SCIMGroupsTestType)

	// Acquire the shared SCIM client.
	s.logger.Info("scim_groups setup: acquiring shared SCIM client", "workload", s.config.Workload)
	sc, err := scimAcquireSharedClient(client, s.config.SeedConcurrency)
	if err != nil {
		return nil, fmt.Errorf("scim_groups setup: %w", err)
	}

	result := &SCIMGroups{
		sc:         sc,
		config:     s.config,
		logger:     s.logger,
		namespace:  sc.namespace,
		pathPrefix: "/v1/identity/scim/v2",
	}

	switch s.config.Workload {

	case scimGroupWorkloadCreate, scimGroupWorkloadCreateEmpty:
		// Scope "gc" vs "ge" keeps group_create and group_create_empty pools
		// distinct — both share the same runID but must not create the same name.
		scope := "gc"
		if s.config.Workload == scimGroupWorkloadCreateEmpty {
			scope = "ge"
		}
		result.createGroupNames = make([]string, s.config.GroupCount)
		for i := range s.config.GroupCount {
			result.createGroupNames[i] = scimCreateGroupDisplayName(sc.runID, scope, i)
		}
		s.logger.Info("scim_groups setup: group_create pool ready",
			"pool_size", s.config.GroupCount, "members_per_group", s.config.MembersPerGroup,
		)

		// group_create_empty has MembersPerGroup=0 so this block is skipped.
		if s.config.MembersPerGroup > 0 {
			seedCount := s.config.UserSeedCount
			if seedCount < s.config.MembersPerGroup {
				seedCount = s.config.MembersPerGroup
			}
			s.logger.Info("scim_groups setup: seeding SCIM-owned users for group membership", "count", seedCount)
			entityIDs, err := seedSCIMUsers(s.logger, client, sc.scimToken, sc.runID, "gm", sc.namespace, s.config.SeedConcurrency, seedCount)
			if err != nil {
				return nil, fmt.Errorf("scim_groups setup: seeding member users: %w", err)
			}
			result.scimEntityIDs = entityIDs
			s.logger.Info("scim_groups setup: member users seeded", "count", len(entityIDs))
		}

	case scimGroupWorkloadAdopt:
		s.logger.Info("scim_groups setup: seeding unmanaged adoption groups", "count", s.config.GroupCount)
		groupIDs := make([]string, s.config.GroupCount)
		groupNames := make([]string, s.config.GroupCount)

		err = runPhase(s.logger, "seed adoption groups", s.config.SeedConcurrency, s.config.GroupCount, func(i int) error {
			name := scimAdoptGroupName(sc.runID, i)
			resp, err := client.Logical().Write("identity/group", map[string]any{
				"name": name,
				"type": "internal",
			})
			if err != nil {
				return fmt.Errorf("creating adopt group %d (%q): %w", i, name, err)
			}
			id, err := idFromResponse(resp)
			if err != nil {
				return fmt.Errorf("reading adopt group id %d: %w", i, err)
			}
			groupIDs[i] = id
			groupNames[i] = name
			s.logger.Debug("scim_groups setup: seeded adoption group",
				"index", i, "group_name", name, "group_id", id,
			)
			return nil
		}, "total", s.config.GroupCount)
		if err != nil {
			return nil, fmt.Errorf("scim_groups setup: seeding adoption groups: %w", err)
		}
		result.adoptGroupIDs = groupIDs
		result.adoptGroupNames = groupNames
		s.logger.Info("scim_groups setup: adoption groups seeded", "count", s.config.GroupCount)

	case scimGroupWorkloadList:
		// Seed real, findable groups so filter tests exercise an actual lookup
		// instead of running against an empty namespace.
		if s.config.SeedGroupCount > 0 {
			s.logger.Info("scim_groups setup: seeding groups for filter tests", "count", s.config.SeedGroupCount)
			if err := seedSCIMGroups(s.logger, client, sc.scimToken, sc.runID, "lg", sc.namespace, s.config.SeedConcurrency, s.config.SeedGroupCount); err != nil {
				return nil, fmt.Errorf("scim_groups setup: seeding filter-test groups: %w", err)
			}
		}
	}

	result.header = scimHeader(sc.scimToken, sc.namespace)

	if s.config.Workload == scimGroupWorkloadList {
		// Deterministic — matches the name seedSCIMGroups assigned to index 0,
		// with no need to inspect any HTTP response.
		seedGroupName := scimCreateGroupDisplayName(sc.runID, "lg", 0)
		result.listURLs = make([]string, len(s.config.Filters))
		for i, f := range s.config.Filters {
			f = strings.ReplaceAll(f, scimFilterSeedGroupToken, seedGroupName)
			u := "/v1/identity/scim/v2/Groups"
			if f != "" {
				u += "?filter=" + url.QueryEscape(f)
			}
			result.listURLs[i] = u
		}
		s.logger.Info("scim_groups setup: list URL variants built", "count", len(result.listURLs))
	}

	return result, nil
}

func (s *SCIMGroups) Target(client *api.Client) vegeta.Target {
	switch s.config.Workload {

	case scimGroupWorkloadCreate:
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		poolIdx := int(idx % int64(len(s.createGroupNames)))
		displayName := s.createGroupNames[poolIdx]

		var memberIDs []string
		if s.config.MembersPerGroup > 0 && len(s.scimEntityIDs) > 0 {
			n := len(s.scimEntityIDs)
			memberIDs = make([]string, s.config.MembersPerGroup)
			for m := range s.config.MembersPerGroup {
				memberIDs[m] = s.scimEntityIDs[(int(poolIdx)*s.config.MembersPerGroup+m)%n]
			}
		}

		s.logger.Debug("scim_groups target: group_create",
			"pool_idx", poolIdx, "display_name", displayName, "member_count", len(memberIDs),
		)

		// Sentinel ?_w=create distinguishes this target from group_create_empty
		// in the reporter. group_create (w=20) sorts before group_create_empty
		// (w=10), so the reporter checks this longer prefix first.
		return vegeta.Target{
			Method: http.MethodPost,
			URL:    client.Address() + s.pathPrefix + "/Groups?_w=create",
			Header: s.header,
			Body:   scimGroupCreateBody(displayName, memberIDs),
		}

	case scimGroupWorkloadCreateEmpty:
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		poolIdx := int(idx % int64(len(s.createGroupNames)))
		displayName := s.createGroupNames[poolIdx]

		s.logger.Debug("scim_groups target: group_create_empty",
			"pool_idx", poolIdx, "display_name", displayName,
		)

		// ?_w=empty is the sentinel for this target. It must NOT be a string
		// prefix of ?_w=create — and it isn't. The reporter checks group_create's
		// prefix first (higher weight), fails to match, then reaches this prefix.
		return vegeta.Target{
			Method: http.MethodPost,
			URL:    client.Address() + s.pathPrefix + "/Groups?_w=empty",
			Header: s.header,
			Body:   scimGroupCreateBody(displayName, nil),
		}

	case scimGroupWorkloadAdopt:
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		poolIdx := int(idx % int64(len(s.adoptGroupIDs)))
		groupID := s.adoptGroupIDs[poolIdx]
		displayName := s.adoptGroupNames[poolIdx]

		s.logger.Debug("scim_groups target: group_adopt",
			"pool_idx", poolIdx, "group_id", groupID, "display_name", displayName,
		)

		return vegeta.Target{
			Method: http.MethodPut,
			URL:    client.Address() + s.pathPrefix + "/Groups/" + groupID,
			Header: s.header,
			Body:   scimGroupAdoptBody(displayName),
		}

	default: // scimGroupWorkloadList
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		urlIdx := int(idx % int64(len(s.listURLs)))

		s.logger.Debug("scim_groups target: group_list", "url_idx", urlIdx, "url", s.listURLs[urlIdx])

		return vegeta.Target{
			Method: http.MethodGet,
			URL:    client.Address() + s.listURLs[urlIdx],
			Header: s.header,
		}
	}
}

func (s *SCIMGroups) Cleanup(client *api.Client) error {
	// group_adopt: only the pool indices past the final atomicIdx were never
	// sent as an adopt request at all, so they're guaranteed to still be plain
	// unmanaged groups. Anything at or before that index may have been adopted
	// (SCIM-owned) and must be left to delete-linked-resources' async cleanup
	// worker instead — deleting it here directly would race that worker and
	// return "SCIM-managed resources must be modified through SCIM".
	if s.config.Workload == scimGroupWorkloadAdopt {
		touched := int(atomic.LoadInt64(&s.atomicIdx))
		if touched < len(s.adoptGroupIDs) {
			scimSharedMu.Lock()
			s.sc.adoptGroupIDs = append(s.sc.adoptGroupIDs, s.adoptGroupIDs[touched:]...)
			scimSharedMu.Unlock()
		}
	}

	s.logger.Info("scim_groups cleanup: releasing shared SCIM client reference")
	// All SCIM-owned resources (created users, created groups, adopted users,
	// adopted groups) belong to the single shared client. The last block to
	// release calls SCIMCleanup with delete-linked-resources=true, which removes
	// everything in one atomic Vault operation. No per-resource delete loops
	// are needed and concurrent cleanup races are impossible.
	return scimReleaseSharedClient(client)
}

func (s *SCIMGroups) GetTargetInfo() TargetInfo {
	switch s.config.Workload {
	case scimGroupWorkloadCreate:
		return TargetInfo{method: http.MethodPost, pathPrefix: s.pathPrefix + "/Groups?_w=create"}
	case scimGroupWorkloadCreateEmpty:
		return TargetInfo{method: http.MethodPost, pathPrefix: s.pathPrefix + "/Groups?_w=empty"}
	case scimGroupWorkloadAdopt:
		return TargetInfo{method: http.MethodPut, pathPrefix: s.pathPrefix + "/Groups"}
	default: // scimGroupWorkloadList
		return TargetInfo{method: http.MethodGet, pathPrefix: s.pathPrefix + "/Groups"}
	}
}

func (s *SCIMGroups) Flags(fs *flag.FlagSet) {}
