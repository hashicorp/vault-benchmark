// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

// target_scim_users.go implements three SCIM user workloads:
//
//   - user_create: POST /scim/v2/Users with a fresh unique userName each time.
//     Each request sends a name from a pre-generated pool so Vault always
//     creates a new entity. No two requests in one pass share a name.
//
//   - user_adopt: POST /scim/v2/Users with a userName matching a pre-seeded
//     unmanaged alias. Setup seeds user_count entities (entity name ≠ alias
//     name, matching real IdP login behaviour). The attack phase adopts each
//     one exactly once per cycle through the pool.
//
//   - user_list: GET /scim/v2/Users with a round-robin selection of filter
//     expressions (including the bare, no-filter case).
//
// All three workloads share a single SCIM client per benchmark run
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
	SCIMUsersTestType = "scim_users"

	scimUserWorkloadCreate = "user_create"
	scimUserWorkloadAdopt  = "user_adopt"
	scimUserWorkloadList   = "user_list"
)

func init() {
	TestList[SCIMUsersTestType] = func() BenchmarkBuilder { return &SCIMUsers{} }
}

// SCIMUsers implements BenchmarkBuilder for SCIM user workloads.
type SCIMUsers struct {
	pathPrefix string
	header     http.Header
	logger     hclog.Logger

	// sc is the shared SCIM client; all workloads in a run share one client.
	sc *scimSharedClient

	// namespace is the Vault namespace set on the admin client (may be empty).
	namespace string

	// user_create: pool of unique userNames. atomicIdx cycles through the pool.
	createUserNames []string
	// user_adopt: pool of alias names for pre-seeded unmanaged entities.
	adoptUserNames []string
	// user_list: pre-built URL strings (one per filter variant).
	listURLs []string

	atomicIdx int64 // shared counter; incremented on each Target() call

	config *SCIMUsersConfig
}

// SCIMUsersConfig holds all HCL-configurable parameters for the SCIM users target.
type SCIMUsersConfig struct {
	// Workload selects which of the three user workloads to run.
	// One of: "user_create" | "user_adopt" | "user_list"
	Workload string `hcl:"workload,optional"`

	// UserCount is:
	//   user_create: size of the unique-name pool (set ≥ rps × duration_seconds)
	//   user_adopt:  number of pre-seeded unmanaged entities to create
	//   user_list:   ignored (no pool needed)
	UserCount int `hcl:"user_count,optional"`

	// Filters is the list of SCIM filter query-strings cycled for user_list.
	// An empty string means "no filter" (returns all users).
	// Example: ["", "userName eq \"alice@example.com\"", "meta.lastModified gt \"2020-01-01T00:00:00Z\""]
	// Defaults to [""] (bare list, no filter) when omitted. A filter may contain
	// the token $SEED_USERNAME, which is substituted with the userName of a
	// pre-seeded user (see SeedUserCount) so a point-lookup filter is guaranteed
	// to match real data.
	Filters []string `hcl:"filters,optional"`

	// SeedUserCount pre-seeds this many SCIM-owned users during setup, purely as
	// queryable data for user_list filter tests. Ignored for other workloads.
	SeedUserCount int `hcl:"seed_user_count,optional"`
}

func (s *SCIMUsers) ParseConfig(body hcl.Body) error {
	testConfig := &struct {
		Config *SCIMUsersConfig `hcl:"config,block"`
	}{
		Config: &SCIMUsersConfig{
			Workload:  scimUserWorkloadCreate,
			UserCount: 200,
			Filters:   []string{""},
		},
	}

	diags := gohcl.DecodeBody(body, nil, testConfig)
	if diags.HasErrors() {
		return fmt.Errorf("error decoding scim_users config: %v", diags)
	}

	c := testConfig.Config
	s.config = c

	switch c.Workload {
	case scimUserWorkloadCreate, scimUserWorkloadAdopt:
		if c.UserCount <= 0 {
			return fmt.Errorf("scim_users: user_count must be > 0 for workload %q", c.Workload)
		}
	case scimUserWorkloadList:
		if len(c.Filters) == 0 {
			c.Filters = []string{""}
		}
		if c.SeedUserCount < 0 {
			return fmt.Errorf("scim_users: seed_user_count must be >= 0")
		}
	default:
		return fmt.Errorf("scim_users: invalid workload %q; must be one of %q, %q, %q",
			c.Workload, scimUserWorkloadCreate, scimUserWorkloadAdopt, scimUserWorkloadList)
	}

	return nil
}

func (s *SCIMUsers) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	s.logger = targetLogger.Named(SCIMUsersTestType)

	// Acquire the shared SCIM client — created once for the whole run,
	// reused by every scim_users and scim_groups test block.
	s.logger.Info("scim_users setup: acquiring shared SCIM client", "workload", s.config.Workload)
	sc, err := scimAcquireSharedClient(client)
	if err != nil {
		return nil, fmt.Errorf("scim_users setup: %w", err)
	}

	result := &SCIMUsers{
		sc:         sc,
		config:     s.config,
		logger:     s.logger,
		namespace:  sc.namespace,
		pathPrefix: "/v1/identity/scim/v2",
	}

	switch s.config.Workload {

	case scimUserWorkloadCreate:
		// Pre-generate a pool of unique userNames. No Vault state is created
		// here; the names are just unique strings that Vault has never seen.
		// Scope "uc" (user_create) keeps these distinct from "gm" (group member)
		// users seeded by group_create, which share the same runID.
		result.createUserNames = make([]string, s.config.UserCount)
		for i := range s.config.UserCount {
			result.createUserNames[i] = scimCreateUserName(sc.runID, "uc", i)
		}
		s.logger.Info("scim_users setup: user_create pool ready", "pool_size", s.config.UserCount)

	case scimUserWorkloadAdopt:
		// Seed N unmanaged entities. Each entity has:
		//   - entity name  = scimAdoptEntityName(runID, i)
		//   - alias name   = scimAdoptUserAliasName(runID, i)
		//   - mount        = the shared SCIM client's alias_mount_accessor
		// The alias name becomes the SCIM userName in POST /Users, triggering
		// adoption. The entity name is intentionally different — mirroring real
		// login-created entities (e.g. Entra SAML login sets the entity name to
		// the internal Vault ID, the alias to the UPN).
		s.logger.Info("scim_users setup: seeding unmanaged adoption targets", "count", s.config.UserCount)
		aliasNames := make([]string, s.config.UserCount)

		err = runPhase(s.logger, "seed adoption entities", identityConcurrency, s.config.UserCount, func(i int) error {
			entityName := scimAdoptEntityName(sc.runID, i)
			aliasName := scimAdoptUserAliasName(sc.runID, i)

			resp, err := client.Logical().Write("identity/entity", map[string]any{
				"name": entityName,
			})
			if err != nil {
				return fmt.Errorf("creating adopt entity %d (%q): %w", i, entityName, err)
			}
			entityID, err := idFromResponse(resp)
			if err != nil {
				return fmt.Errorf("reading adopt entity id %d: %w", i, err)
			}

			if _, err = client.Logical().Write("identity/entity-alias", map[string]any{
				"name":           aliasName,
				"canonical_id":   entityID,
				"mount_accessor": sc.aliasMountAccessor,
			}); err != nil {
				return fmt.Errorf("creating alias %q for adopt entity %d: %w", aliasName, i, err)
			}

			aliasNames[i] = aliasName
			s.logger.Debug("scim_users setup: seeded adoption target",
				"index", i, "entity_name", entityName, "alias_name", aliasName, "entity_id", entityID,
			)
			return nil
		}, "total", s.config.UserCount)
		if err != nil {
			return nil, fmt.Errorf("scim_users setup: seeding adoption entities: %w", err)
		}
		result.adoptUserNames = aliasNames
		s.logger.Info("scim_users setup: adoption targets seeded", "count", s.config.UserCount)

	case scimUserWorkloadList:
		// Seed real, findable users so filter tests exercise an actual lookup
		// instead of running against an empty namespace.
		if s.config.SeedUserCount > 0 {
			s.logger.Info("scim_users setup: seeding users for filter tests", "count", s.config.SeedUserCount)
			if _, err := seedSCIMUsers(s.logger, client, sc.scimToken, sc.runID, "lf", sc.namespace, s.config.SeedUserCount); err != nil {
				return nil, fmt.Errorf("scim_users setup: seeding filter-test users: %w", err)
			}
		}
	}

	result.header = scimHeader(sc.scimToken, sc.namespace)

	if s.config.Workload == scimUserWorkloadList {
		// Deterministic — matches the name seedSCIMUsers assigned to index 0,
		// with no need to inspect any HTTP response.
		seedUserName := scimCreateUserName(sc.runID, "lf", 0)
		result.listURLs = make([]string, len(s.config.Filters))
		for i, f := range s.config.Filters {
			f = strings.ReplaceAll(f, scimFilterSeedUserToken, seedUserName)
			u := "/v1/identity/scim/v2/Users"
			if f != "" {
				u += "?filter=" + url.QueryEscape(f)
			}
			result.listURLs[i] = u
		}
		s.logger.Info("scim_users setup: list URL variants built", "count", len(result.listURLs))
	}

	return result, nil
}

func (s *SCIMUsers) Target(client *api.Client) vegeta.Target {
	switch s.config.Workload {

	case scimUserWorkloadCreate:
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		poolIdx := int(idx % int64(len(s.createUserNames)))
		userName := s.createUserNames[poolIdx]
		externalID := "ext-" + userName

		s.logger.Debug("scim_users target: user_create", "pool_idx", poolIdx, "user_name", userName)

		// The ?_w=create sentinel gives user_create a longer, more specific URL
		// than user_adopt. The reporter's HasPrefix check runs in weight-sorted
		// order and stops at the first match. Because HasPrefix(bare_url,
		// sentinel_url) is FALSE and HasPrefix(sentinel_url, sentinel_url) is
		// TRUE, create results match only create and adopt results fall through
		// to match adopt's bare prefix. Without the sentinel the bare create
		// prefix would swallow all adopt results too.
		return vegeta.Target{
			Method: http.MethodPost,
			URL:    client.Address() + s.pathPrefix + "/Users?_w=create",
			Header: s.header,
			Body:   scimUserCreateBody(userName, externalID),
		}

	case scimUserWorkloadAdopt:
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		poolIdx := int(idx % int64(len(s.adoptUserNames)))
		userName := s.adoptUserNames[poolIdx]
		externalID := "ext-" + userName

		s.logger.Debug("scim_users target: user_adopt", "pool_idx", poolIdx, "user_name", userName)

		return vegeta.Target{
			Method: http.MethodPost,
			URL:    client.Address() + s.pathPrefix + "/Users",
			Header: s.header,
			Body:   scimUserAdoptBody(userName, externalID),
		}

	default: // scimUserWorkloadList
		idx := atomic.AddInt64(&s.atomicIdx, 1) - 1
		urlIdx := int(idx % int64(len(s.listURLs)))

		s.logger.Debug("scim_users target: user_list", "url_idx", urlIdx, "url", s.listURLs[urlIdx])

		return vegeta.Target{
			Method: http.MethodGet,
			URL:    client.Address() + s.listURLs[urlIdx],
			Header: s.header,
		}
	}
}

func (s *SCIMUsers) Cleanup(client *api.Client) error {
	// user_adopt: only the pool indices past the final atomicIdx were never sent
	// as an adopt request at all, so they're guaranteed to still be plain
	// unmanaged entities. Anything at or before that index may have been adopted
	// (SCIM-owned) and must be left to delete-linked-resources' async cleanup
	// worker instead — deleting it here directly would race that worker and
	// return "SCIM-managed resources must be modified through SCIM".
	if s.config.Workload == scimUserWorkloadAdopt {
		touched := int(atomic.LoadInt64(&s.atomicIdx))
		if touched < len(s.adoptUserNames) {
			untouched := make([]string, 0, len(s.adoptUserNames)-touched)
			for i := touched; i < len(s.adoptUserNames); i++ {
				untouched = append(untouched, scimAdoptEntityName(s.sc.runID, i))
			}
			scimSharedMu.Lock()
			s.sc.adoptUserNames = append(s.sc.adoptUserNames, untouched...)
			scimSharedMu.Unlock()
		}
	}

	s.logger.Info("scim_users cleanup: releasing shared SCIM client reference")
	// scimReleaseSharedClient decrements the shared refcount. The last block
	// to release triggers delete-linked-resources=true which removes all
	// SCIM-owned entities and groups in one atomic call — no per-resource
	// delete loop needed, and no racing with other blocks' cleanup.
	return scimReleaseSharedClient(client)
}

func (s *SCIMUsers) GetTargetInfo() TargetInfo {
	switch s.config.Workload {
	case scimUserWorkloadCreate:
		return TargetInfo{method: http.MethodPost, pathPrefix: s.pathPrefix + "/Users?_w=create"}
	case scimUserWorkloadAdopt:
		return TargetInfo{method: http.MethodPost, pathPrefix: s.pathPrefix + "/Users"}
	default:
		return TargetInfo{method: http.MethodGet, pathPrefix: s.pathPrefix + "/Users"}
	}
}

func (s *SCIMUsers) Flags(fs *flag.FlagSet) {}
