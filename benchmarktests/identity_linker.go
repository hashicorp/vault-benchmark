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

	"github.com/hashicorp/vault/api"
	"github.com/sethvargo/go-password/password"
)

const userpassMountBase = "userpass"

// identityLinker links generated entities to a userpass auth mount by creating
// userpass users and/or entity aliases so the entities become loginable.
type identityLinker struct {
	password string

	mountPath        string
	userpassAccessor string
}

// newIdentityLinker returns a linker for the run. When needMount is set (any
// aliases or users will be created) it enables a run-scoped userpass mount
// (userpass-<runID>) that Cleanup later disables; otherwise it returns an empty
// linker that touches no mount.
func newIdentityLinker(client *api.Client, runID string, needMount bool) (*identityLinker, error) {
	linker := &identityLinker{}

	if !needMount {
		return linker, nil
	}

	generated, err := generatePassword()
	if err != nil {
		return nil, fmt.Errorf("error generating userpass password: %w", err)
	}
	linker.password = generated

	mountPath := userpassMountBase + "-" + runID
	accessor, err := ensureMount(client, mountPath)
	if err != nil {
		return nil, err
	}

	linker.userpassAccessor = accessor
	linker.mountPath = mountPath

	return linker, nil
}

// linkEntity creates a userpass user and/or entity alias for name, as requested
// by the caller. Both are named after the entity (1:1) so callers can derive the
// username from an index.
func (h *identityLinker) linkEntity(client *api.Client, name, entityID string, createAlias, createUser bool) error {
	if createUser {
		// ToSlash keeps forward slashes on Windows.
		userPath := filepath.ToSlash(filepath.Join("auth", h.mountPath, "users", name))
		_, err := client.Logical().Write(userPath, map[string]any{
			"password": h.password,
		})
		if err != nil {
			return fmt.Errorf("error creating userpass user %q: %w", name, err)
		}
	}

	if createAlias {
		_, err := client.Logical().Write("identity/entity-alias", map[string]any{
			"name":           name,
			"canonical_id":   entityID,
			"mount_accessor": h.userpassAccessor,
		})
		if err != nil {
			return fmt.Errorf("error creating entity alias %q: %w", name, err)
		}
	}

	return nil
}

// validateLogin logs in as one seeded user and confirms the token resolves to
// expectedEntityID.
func (h *identityLinker) validateLogin(client *api.Client, name, expectedEntityID string) error {
	loginPath := filepath.ToSlash(filepath.Join("auth", h.mountPath, "login", name))
	secret, err := client.Logical().Write(loginPath, map[string]any{
		"password": h.password,
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

func ensureMount(client *api.Client, mountPath string) (string, error) {
	authMountKey := mountPath + "/"

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", fmt.Errorf("error listing auth mounts: %w", err)
	}

	if authMount, ok := authMounts[authMountKey]; ok {
		if authMount.Type != "userpass" {
			return "", fmt.Errorf("auth mount %q exists with type %q, expected userpass", mountPath, authMount.Type)
		}

		if authMount.Accessor == "" {
			return "", fmt.Errorf("auth mount %q has empty accessor", mountPath)
		}

		return authMount.Accessor, nil
	}

	if err := client.Sys().EnableAuthWithOptions(mountPath, &api.EnableAuthOptions{Type: "userpass"}); err != nil {
		return "", fmt.Errorf("error enabling userpass auth mount %q: %w", mountPath, err)
	}

	authMounts, err = client.Sys().ListAuth()
	if err != nil {
		return "", fmt.Errorf("error listing auth mounts after enabling %q: %w", mountPath, err)
	}

	authMount, ok := authMounts[authMountKey]
	if !ok {
		return "", fmt.Errorf("auth mount %q not found after enable", mountPath)
	}

	if authMount.Accessor == "" {
		return "", fmt.Errorf("auth mount %q has empty accessor after enable", mountPath)
	}

	return authMount.Accessor, nil
}

// generatePassword returns a strong throwaway password shared by all users.
func generatePassword() (string, error) {
	return password.Generate(64, 10, 0, false, true)
}

// entityName derives a run-unique entity name of the form mountName-entity-runID-idx.
func entityName(mountName, runID string, idx int) string {
	return mountName + "-entity-" + runID + "-" + strconv.Itoa(idx)
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

// identityIDFromResponse extracts the "id" field from an entity/group response.
func identityIDFromResponse(resp *api.Secret) (string, error) {
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

// resolveGroups turns the group allocation into the number of groups that hold
// members and the members per filled group (E is entity_count):
//
//	even  (default): entities partitioned across all groups (~E/group_count each)
//	empty          : no group holds members
//	max            : every group holds all E entities
//	count+size     : count groups hold size members each, the rest empty
func resolveGroups(g *GroupConfig, groupCount, entityCount int) (filled, size int, err error) {
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
	case "", "even":
		return groupCount, ceilDiv(entityCount, groupCount), nil
	case "empty":
		return 0, 0, nil
	case "max":
		return groupCount, entityCount, nil
	default:
		return 0, 0, fmt.Errorf("invalid groups preset %q: must be \"even\", \"empty\", or \"max\"", g.Preset)
	}
}

// configureAttack returns the method and path prefix for the selected workload
// (populate falls back to a health check).
func configureAttack(cfg *IdentityConfig, authLinker *identityLinker) (method, pathPrefix string) {
	switch cfg.Workload {
	case identityWorkloadLogin:
		return http.MethodPost, "/v1/" + filepath.ToSlash(filepath.Join("auth", authLinker.mountPath))
	case identityWorkloadGroupRead:
		return http.MethodGet, "/v1/identity/group/id/"
	default: // identityWorkloadPopulate
		return http.MethodGet, identityNoWorkloadPath
	}
}

// deleteIDs deletes each id under pathPrefix concurrently.
func deleteIDs(client *api.Client, pathPrefix string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	jobs := make(chan string, identityConcurrency)
	errs := make(chan error, len(ids))

	var wg sync.WaitGroup
	for range identityConcurrency {
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
