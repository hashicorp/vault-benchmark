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

// objectName derives a run-unique name of the form mountName-typ-runID-idx.
// Single naming authority for creation and cleanup; names are never stored.
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
// wraparound, so membership is deterministic across any entity count.
func selectGroupMembers(entityIDs []string, groupIndex, groupSize int) []string {
	members := make([]string, 0, groupSize)
	start := (groupIndex * groupSize) % len(entityIDs)
	for offset := range groupSize {
		members = append(members, entityIDs[(start+offset)%len(entityIDs)])
	}
	return members
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

	jobs := make(chan int, identityConcurrency)
	errs := make(chan error, identityConcurrency) // bounded to workers so sends never block

	var allErrs []error
	collected := make(chan struct{})
	go func() { // sole writer of allErrs; no synchronization needed
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
