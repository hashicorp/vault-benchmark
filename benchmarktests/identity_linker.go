// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strconv"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/sethvargo/go-password/password"
)

// TODO(refactor-pr): see the full refactor checklist at the top of
// target_identity.go. Phase 1 renames and the phase 2 mount hardcoding are done.

const userpassMountBase = "userpass"

// identityLinker links generated entities to a userpass auth mount by creating
// userpass users and/or entity aliases so the entities become loginable.
type identityLinker struct {
	createAliases bool
	createUsers   bool
	password      string

	mountPath        string
	userpassAccessor string
}

// identityLinkerConfig configures how identity setup links entities to userpass.
type identityLinkerConfig struct {
	CreateAliases bool
	CreateUsers   bool
	RandomMounts  bool
}

func newIdentityLinker(client *api.Client, cfg identityLinkerConfig) (*identityLinker, error) {
	helper := &identityLinker{
		createAliases: cfg.CreateAliases,
		createUsers:   cfg.CreateUsers,
	}

	if !cfg.CreateAliases && !cfg.CreateUsers {
		return helper, nil
	}

	generated, err := generatePassword()
	if err != nil {
		return nil, fmt.Errorf("error generating userpass password: %w", err)
	}
	helper.password = generated

	authMountPath := userpassMountBase
	if cfg.RandomMounts {
		runID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("error generating userpass mount run id: %w", err)
		}
		authMountPath = authMountPath + "-" + runID
	}

	accessor, resolvedMountPath, err := ensureMount(client, authMountPath)
	if err != nil {
		return nil, err
	}

	helper.userpassAccessor = accessor
	helper.mountPath = resolvedMountPath

	return helper, nil
}

// linkEntity creates the userpass user and/or entity alias for name. Both are
// named after the entity (1:1) so callers can derive the username from an index.
func (h *identityLinker) linkEntity(client *api.Client, name, entityID string) error {
	if h.createUsers {
		// ToSlash keeps forward slashes on Windows.
		userPath := filepath.ToSlash(filepath.Join("auth", h.mountPath, "users", name))
		_, err := client.Logical().Write(userPath, map[string]any{
			"password": h.password,
		})
		if err != nil {
			return fmt.Errorf("error creating userpass user %q: %w", name, err)
		}
	}

	if h.createAliases {
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

// validateLogin logs in as one user and confirms the token resolves to
// expectedEntityID. Alias-only datasets first get a throwaway probe user (no
// other credential exists).
func (h *identityLinker) validateLogin(client *api.Client, name, expectedEntityID string) error {
	if h.userpassAccessor == "" {
		return fmt.Errorf("cannot validate login resolution: no userpass mount configured")
	}

	if !h.createUsers {
		userPath := filepath.ToSlash(filepath.Join("auth", h.mountPath, "users", name))
		if _, err := client.Logical().Write(userPath, map[string]any{
			"password": h.password,
		}); err != nil {
			return fmt.Errorf("error creating validation user %q: %w", name, err)
		}
	}

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

func ensureMount(client *api.Client, mountPath string) (string, string, error) {
	authMountKey := mountPath + "/"

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("error listing auth mounts: %w", err)
	}

	if authMount, ok := authMounts[authMountKey]; ok {
		if authMount.Type != "userpass" {
			return "", "", fmt.Errorf("auth mount %q exists with type %q, expected userpass", mountPath, authMount.Type)
		}

		if authMount.Accessor == "" {
			return "", "", fmt.Errorf("auth mount %q has empty accessor", mountPath)
		}

		return authMount.Accessor, mountPath, nil
	}

	if err := client.Sys().EnableAuthWithOptions(mountPath, &api.EnableAuthOptions{Type: "userpass"}); err != nil {
		return "", "", fmt.Errorf("error enabling userpass auth mount %q: %w", mountPath, err)
	}

	authMounts, err = client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("error listing auth mounts after enabling %q: %w", mountPath, err)
	}

	authMount, ok := authMounts[authMountKey]
	if !ok {
		return "", "", fmt.Errorf("auth mount %q not found after enable", mountPath)
	}

	if authMount.Accessor == "" {
		return "", "", fmt.Errorf("auth mount %q has empty accessor after enable", mountPath)
	}

	return authMount.Accessor, mountPath, nil
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

// sampleIndices returns k distinct random 1-based indices in [1, n] (all when
// k >= n). Callers must pass 0 < k <= n.
func sampleIndices(n, k int) []int {
	if k >= n {
		idxs := make([]int, n)
		for i := range idxs {
			idxs[i] = i + 1
		}
		return idxs
	}

	seen := make(map[int]struct{}, k)
	idxs := make([]int, 0, k)
	for len(idxs) < k {
		candidate := rand.Intn(n) + 1
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		idxs = append(idxs, candidate)
	}
	return idxs
}
