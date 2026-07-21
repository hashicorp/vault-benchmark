// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
)

const userpassMountBase = "userpass"

func userpassMountPath(runID string) string {
	return userpassMountBase + "-" + runID
}

func objectName(mountName, typ, runID string, idx int) string {
	return mountName + "-" + typ + "-" + runID + "-" + strconv.Itoa(idx)
}

// enableUserpass returns the mount accessor -- the one value later steps can't
// derive (aliases bind to the mount by accessor, not path).
func enableUserpass(client *api.Client, runID string) (accessor string, err error) {
	mountPath := userpassMountPath(runID)
	if err := client.Sys().EnableAuthWithOptions(mountPath, &api.EnableAuthOptions{Type: "userpass"}); err != nil {
		return "", fmt.Errorf("error enabling userpass auth mount %q: %w", mountPath, err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", fmt.Errorf("error listing auth mounts after enabling %q: %w", mountPath, err)
	}
	mount, ok := mounts[mountPath+"/"]
	if !ok {
		return "", fmt.Errorf("auth mount %q not found after enable", mountPath)
	}
	if mount.Accessor == "" {
		return "", fmt.Errorf("auth mount %q has empty accessor after enable", mountPath)
	}

	return mount.Accessor, nil
}

func addEntityAlias(client *api.Client, accessor, name, entityID string) error {
	_, err := client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           name,
		"canonical_id":   entityID,
		"mount_accessor": accessor,
	})
	if err != nil {
		return fmt.Errorf("error creating entity alias %q: %w", name, err)
	}
	return nil
}

func addUserpassUser(client *api.Client, mountPath, name string) error {
	userPath := filepath.ToSlash(filepath.Join("auth", mountPath, "users", name)) // ToSlash for Windows
	_, err := client.Logical().Write(userPath, map[string]any{
		"password": identityPassword,
	})
	if err != nil {
		return fmt.Errorf("error creating userpass user %q: %w", name, err)
	}
	return nil
}

func validateLogin(client *api.Client, mountPath, name, expectedEntityID string) error {
	loginPath := filepath.ToSlash(filepath.Join("auth", mountPath, "login", name))
	secret, err := client.Logical().Write(loginPath, map[string]any{
		"password": identityPassword,
	})
	if err != nil {
		return fmt.Errorf("login resolution check failed for user %q: %w", name, err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("login resolution check for user %q returned no auth data", name)
	}

	if secret.Auth.EntityID != expectedEntityID {
		return fmt.Errorf("login for user %q resolved to entity %q, expected %q",
			name, secret.Auth.EntityID, expectedEntityID)
	}

	return nil
}

func idFromResponse(resp *api.Secret) (string, error) {
	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("empty response data")
	}

	rawID, ok := resp.Data["id"]
	if !ok {
		return "", fmt.Errorf("response missing id field")
	}

	id, ok := rawID.(string)
	if !ok || id == "" {
		return "", fmt.Errorf("response id is not a non-empty string")
	}

	return id, nil
}

// selectGroupMembers returns groupSize entity ids for groupIndex using
// wraparound so membership is deterministic across any entity count.
// Returns a sub-slice when the window fits without wrapping (zero copy);
// allocates only when the window wraps past the end of entityIDs.
func selectGroupMembers(entityIDs []string, groupIndex, groupSize int) []string {
	n := len(entityIDs)
	start := (groupIndex * groupSize) % n
	if start+groupSize <= n {
		return entityIDs[start : start+groupSize]
	}
	members := make([]string, 0, groupSize)
	for offset := range groupSize {
		members = append(members, entityIDs[(start+offset)%n])
	}
	return members
}

// selectPolicyNames returns polSize policy names for entityIndex using
// wraparound so assignment is deterministic across any policy count.
// Returns a sub-slice when the window fits without wrapping (zero copy);
// allocates only when the window wraps past the end of policyNames.
func selectPolicyNames(policyNames []string, entityIndex, polSize int) []string {
	n := len(policyNames)
	start := (entityIndex * polSize) % n
	if start+polSize <= n {
		return policyNames[start : start+polSize]
	}
	selected := make([]string, 0, polSize)
	for offset := range polSize {
		selected = append(selected, policyNames[(start+offset)%n])
	}
	return selected
}

// parseGroups resolves the group allocation into (filled, size):
//
//	balanced (default): ~entity_count/group_count members per group
//	empty             : no members
//	full              : all entities in every group
//	count+size        : count groups get size members, the rest empty
func parseGroups(g *GroupConfig, groupCount, entityCount int) (filled, size int, err error) {
	if groupCount <= 0 {
		return 0, 0, nil
	}
	if g == nil {
		return groupCount, ceilDiv(entityCount, groupCount), nil
	}

	if g.Count > 0 || g.Size > 0 {
		if g.Preset != "" {
			return 0, 0, fmt.Errorf("groups: set either preset or count+size, not both")
		}
		if g.Count < 0 || g.Count > groupCount {
			return 0, 0, fmt.Errorf("groups.count (%d) must be in [0, group_count=%d]", g.Count, groupCount)
		}
		if g.Size < 0 || g.Size > entityCount {
			return 0, 0, fmt.Errorf("groups.size (%d) must be in [0, entity_count=%d]", g.Size, entityCount)
		}
		return g.Count, g.Size, nil
	}

	switch g.Preset {
	case "", "balanced":
		return groupCount, ceilDiv(entityCount, groupCount), nil
	case "empty":
		return 0, 0, nil
	case "full":
		return groupCount, entityCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid groups preset %q: must be \"balanced\", \"empty\", or \"full\"", g.Preset)
	}
}

// parseAliases resolves the alias allocation into (filled, size):
//
//	balanced (default): ~alias_count/entity_count aliases per entity
//	empty             : no aliases
//	full              : alias_count aliases on every entity
//	count+size        : count entities get size aliases, the rest empty
func parseAliases(a *AliasesConfig, aliasCount, entityCount int) (filled, size int, err error) {
	if aliasCount <= 0 {
		return 0, 0, nil
	}
	if a == nil {
		return entityCount, ceilDiv(aliasCount, entityCount), nil
	}

	if a.Count > 0 || a.Size > 0 {
		if a.Preset != "" {
			return 0, 0, fmt.Errorf("aliases: set either preset or count+size, not both")
		}
		if a.Count < 0 || a.Count > entityCount {
			return 0, 0, fmt.Errorf("aliases.count (%d) must be in [0, entity_count=%d]", a.Count, entityCount)
		}
		if a.Size < 0 || a.Size > aliasCount {
			return 0, 0, fmt.Errorf("aliases.size (%d) must be in [0, alias_count=%d]", a.Size, aliasCount)
		}
		return a.Count, a.Size, nil
	}

	switch a.Preset {
	case "", "balanced":
		return entityCount, ceilDiv(aliasCount, entityCount), nil
	case "empty":
		return 0, 0, nil
	case "full":
		return entityCount, aliasCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid aliases preset %q: must be \"balanced\", \"empty\", or \"full\"", a.Preset)
	}
}

// parsePolicies resolves the policy allocation into (filled, size):
//
//	balanced (default): ~policy_count/entity_count policies per entity
//	empty             : no policies
//	full              : policy_count policies on every entity
//	count+size        : count entities get size policies, the rest empty
func parsePolicies(p *PoliciesConfig, policyCount, entityCount int) (filled, size int, err error) {
	if policyCount <= 0 {
		return 0, 0, nil
	}
	if p == nil {
		return entityCount, ceilDiv(policyCount, entityCount), nil
	}

	if p.Count > 0 || p.Size > 0 {
		if p.Preset != "" {
			return 0, 0, fmt.Errorf("policies: set either preset or count+size, not both")
		}
		if p.Count < 0 || p.Count > entityCount {
			return 0, 0, fmt.Errorf("policies.count (%d) must be in [0, entity_count=%d]", p.Count, entityCount)
		}
		if p.Size < 0 || p.Size > policyCount {
			return 0, 0, fmt.Errorf("policies.size (%d) must be in [0, policy_count=%d]", p.Size, policyCount)
		}
		return p.Count, p.Size, nil
	}

	switch p.Preset {
	case "", "balanced":
		return entityCount, ceilDiv(policyCount, entityCount), nil
	case "empty":
		return 0, 0, nil
	case "full":
		return entityCount, policyCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid policies preset %q: must be \"balanced\", \"empty\", or \"full\"", p.Preset)
	}
}

func configureAttack(cfg *IdentityConfig, runID string) (method, pathPrefix string) {
	switch cfg.Workload {
	case identityWorkloadLogin:
		return http.MethodPost, "/v1/" + filepath.ToSlash(filepath.Join("auth", userpassMountPath(runID)))
	case identityWorkloadGroupRead:
		return http.MethodGet, "/v1/identity/group/id/"
	default: // identityWorkloadPopulate
		return http.MethodGet, identityNoWorkloadPath
	}
}

func runConcurrent(start, end int, fn func(idx int) error) error {
	if end < start {
		return nil
	}

	n := identityConcurrency
	jobs := make(chan int, n)
	errs := make(chan error, n)

	var allErrs []error
	collected := make(chan struct{})
	go func() {
		for err := range errs {
			allErrs = append(allErrs, err)
		}
		close(collected)
	}()

	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if err := fn(idx); err != nil {
					errs <- err
				}
			}
		}()
	}

	for idx := start; idx <= end; idx++ {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(errs)
	<-collected

	return errors.Join(allErrs...)
}

// runPhase logs start/progress/complete around a concurrent phase.
// A non-positive total is a no-op.
func runPhase(logger hclog.Logger, phase string, total int, fn func(idx int) error, startFields ...any) error {
	if total <= 0 {
		return nil
	}

	start := time.Now()
	logger.Info(phase+" start", append([]any{"total", total}, startFields...)...)

	progressInterval := ceilDiv(total, identityProgressDivisions)
	var done atomic.Int64

	err := runConcurrent(0, total-1, func(idx int) error {
		if err := fn(idx); err != nil {
			return err
		}
		n := done.Add(1)
		if n%int64(progressInterval) == 0 || int(n) == total {
			logger.Info(phase, "progress", fmt.Sprintf("%d/%d", n, total))
		}
		return nil
	})
	if err != nil {
		return err
	}

	logger.Info(phase+" complete", "total", total, "elapsed", time.Since(start).String())
	return nil
}

func deleteConcurrent(logger hclog.Logger, phase string, client *api.Client, pathPrefix string, count int, keyFn func(idx int) string) error {
	return runPhase(logger, phase, count, func(idx int) error {
		key := keyFn(idx)
		if _, err := client.Logical().Delete(pathPrefix + key); err != nil {
			return fmt.Errorf("error deleting %s%s: %w", pathPrefix, key, err)
		}
		return nil
	})
}
