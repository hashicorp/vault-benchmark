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

// userpassMountPath is the run-scoped userpass mount path (userpass-<runID>),
// derived from the run id so setup and cleanup agree without storing it.
func userpassMountPath(runID string) string {
	return userpassMountBase + "-" + runID
}

// objectName derives a run-unique object name of the form mountName-kind-runID-idx
// (kind is "entity" or "group"). It is the single naming authority that creation and
// cleanup re-derive from, so names are never stored.
func objectName(mountName, kind, runID string, idx int) string {
	return mountName + "-" + kind + "-" + runID + "-" + strconv.Itoa(idx)
}

// enableUserpass sets up the run-scoped userpass auth (disabled in Cleanup) and
// returns its accessor, the one value later steps can't derive (aliases bind to
// the mount by accessor, not path).
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

// addEntityAlias binds name -> entityID as an entity alias on the userpass mount
// (via its accessor), so a login as name resolves to that entity. The entity is
// only loginable once addUserpassUser gives name a credential.
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

// addUserpassUser creates a userpass user named name with the shared
// identityPassword on mountPath, making an already-aliased entity loginable.
func addUserpassUser(client *api.Client, mountPath, name string) error {
	// ToSlash keeps forward slashes on Windows.
	userPath := filepath.ToSlash(filepath.Join("auth", mountPath, "users", name))
	_, err := client.Logical().Write(userPath, map[string]any{
		"password": identityPassword,
	})
	if err != nil {
		return fmt.Errorf("error creating userpass user %q: %w", name, err)
	}
	return nil
}

// validateLogin logs in as one seeded user on mountPath and confirms the token
// resolves to expectedEntityID.
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

// idFromResponse extracts the "id" field from an entity/group response.
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

// selectGroupMembers returns groupSize entity ids for groupIndex, walking the
// slice with wraparound so membership is deterministic.
func selectGroupMembers(entityIDs []string, groupIndex, groupSize int) []string {
	members := make([]string, 0, groupSize)
	start := (groupIndex * groupSize) % len(entityIDs)
	for offset := range groupSize {
		members = append(members, entityIDs[(start+offset)%len(entityIDs)])
	}
	return members
}

// parseGroups turns the group allocation into the number of groups that hold
// members and the members per filled group (E is entity_count):
//
//	balanced (default): entities partitioned across all groups (~E/group_count each)
//	empty             : no group holds members
//	full              : every group holds all E entities
//	count+size        : count groups hold size members each, the rest empty
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

// configureAttack returns the method and path prefix for the selected workload
// (populate falls back to a health check).
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

// runConcurrent runs fn for every index in [start, end] across identityConcurrency
// workers, collecting all errors (collect-all). Callers pass 0-based ranges. An
// empty range (end < start) is a no-op.
func runConcurrent(start, end int, fn func(idx int) error) error {
	if end < start {
		return nil
	}

	jobs := make(chan int, identityConcurrency)
	// Buffered to the worker count so a worker never blocks on send while the
	// collector goroutine below drains it.
	errs := make(chan error, identityConcurrency)

	// Collects errors as workers send them, so errs stays small instead of
	// scaling with job count; allErrs is safe unsynchronized since this goroutine
	// is its only writer.
	var allErrs []error
	collected := make(chan struct{})
	go func() {
		for err := range errs {
			allErrs = append(allErrs, err)
		}
		close(collected)
	}()

	var wg sync.WaitGroup
	for range identityConcurrency {
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

// runPhase runs fn concurrently across [0, total), logging a start line (with any
// extra key/value pairs), progress at roughly identityProgressDivisions cadence,
// and a complete line with elapsed time -- the shared shape of every setup and
// cleanup phase that scales with a count. A non-positive total logs nothing and
// runs nothing, so callers don't need their own guard for empty phases.
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

// deleteConcurrent deletes count keys under pathPrefix concurrently, logging
// progress via runPhase. keyFn maps each index to its key (an id from a slice, or
// a name re-derived from the index), so callers that can derive keys avoid
// materializing them.
func deleteConcurrent(logger hclog.Logger, phase string, client *api.Client, pathPrefix string, count int, keyFn func(idx int) string) error {
	return runPhase(logger, phase, count, func(idx int) error {
		key := keyFn(idx)
		if _, err := client.Logical().Delete(pathPrefix + key); err != nil {
			return fmt.Errorf("error deleting %s%s: %w", pathPrefix, key, err)
		}
		return nil
	})
}
