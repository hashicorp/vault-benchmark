// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/sethvargo/go-password/password"
)

// TODO(refactor-pr): see the full refactor checklist at the top of
// target_identity_group_read.go. This file's renames are phase 1
// (-> identity_linker.go, identityLinker, newIdentityLinker, ensureMount,
// normalizeMountPath) and the mount hardcoding is phase 2.

// identityAuthLinkConfig configures how identity setup links generated entities
// to a userpass auth mount so they become loginable.
type identityAuthLinkConfig struct {
	CreateAliases bool
	CreateUsers   bool
	UserpassMount string
	RandomMounts  bool
}

type identityAuthLinkHelper struct {
	createAliases bool
	createUsers   bool
	userPassword  string

	userpassMountPath string
	userpassAccessor  string
}

func newIdentityAuthLinkHelper(client *api.Client, cfg identityAuthLinkConfig) (*identityAuthLinkHelper, error) {
	helper := &identityAuthLinkHelper{
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
	helper.userPassword = generated

	authMountPath := normalizeAuthMountPath(cfg.UserpassMount)
	if cfg.RandomMounts {
		runID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("error generating userpass mount run id: %w", err)
		}
		authMountPath = authMountPath + "-" + runID
	}

	accessor, resolvedMountPath, err := ensureUserpassMountAccessor(client, authMountPath)
	if err != nil {
		return nil, err
	}

	helper.userpassAccessor = accessor
	helper.userpassMountPath = resolvedMountPath

	return helper, nil
}

// linkEntity creates the userpass user (when CreateUsers is set) and then the
// entity alias that connects it (when CreateAliases is set). Both are named after
// the entity (1:1), which callers rely on to derive usernames from an index
// without storing a lookup map.
func (h *identityAuthLinkHelper) linkEntity(client *api.Client, name, entityID string) error {
	if h.createUsers {
		// filepath.Join+ToSlash: build the path portably (forward slashes) even on Windows.
		userPath := filepath.ToSlash(filepath.Join("auth", h.userpassMountPath, "users", name))
		_, err := client.Logical().Write(userPath, map[string]any{
			"password": h.userPassword,
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

// validateLogin is a single-sample, fail-fast check: it logs in as
// one user and confirms the token resolves to expectedEntityID. For alias-only
// datasets it first creates a throwaway probe user, since there is otherwise no
// credential to log in with.
func (h *identityAuthLinkHelper) validateLogin(client *api.Client, name, expectedEntityID string) error {
	if h.userpassAccessor == "" {
		return fmt.Errorf("cannot validate login resolution: no userpass mount configured")
	}

	if !h.createUsers {
		userPath := filepath.ToSlash(filepath.Join("auth", h.userpassMountPath, "users", name))
		if _, err := client.Logical().Write(userPath, map[string]any{
			"password": h.userPassword,
		}); err != nil {
			return fmt.Errorf("error creating validation user %q: %w", name, err)
		}
	}

	loginPath := filepath.ToSlash(filepath.Join("auth", h.userpassMountPath, "login", name))
	secret, err := client.Logical().Write(loginPath, map[string]any{
		"password": h.userPassword,
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

func (h *identityAuthLinkHelper) mountPath() string {
	return h.userpassMountPath
}

func (h *identityAuthLinkHelper) password() string {
	return h.userPassword
}

func ensureUserpassMountAccessor(client *api.Client, mountPath string) (string, string, error) {
	authMountPath := normalizeAuthMountPath(mountPath)
	authMountKey := authMountPath + "/"

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("error listing auth mounts: %w", err)
	}

	if authMount, ok := authMounts[authMountKey]; ok {
		if authMount.Type != "userpass" {
			return "", "", fmt.Errorf("auth mount %q exists with type %q, expected userpass", authMountPath, authMount.Type)
		}

		if authMount.Accessor == "" {
			return "", "", fmt.Errorf("auth mount %q has empty accessor", authMountPath)
		}

		return authMount.Accessor, authMountPath, nil
	}

	if err := client.Sys().EnableAuthWithOptions(authMountPath, &api.EnableAuthOptions{Type: "userpass"}); err != nil {
		return "", "", fmt.Errorf("error enabling userpass auth mount %q: %w", authMountPath, err)
	}

	authMounts, err = client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("error listing auth mounts after enabling %q: %w", authMountPath, err)
	}

	authMount, ok := authMounts[authMountKey]
	if !ok {
		return "", "", fmt.Errorf("auth mount %q not found after enable", authMountPath)
	}

	if authMount.Accessor == "" {
		return "", "", fmt.Errorf("auth mount %q has empty accessor after enable", authMountPath)
	}

	return authMount.Accessor, authMountPath, nil
}

// generatePassword returns a strong throwaway password shared by every
// generated user: 64 chars, 10 digits, no symbols, repeats allowed.
func generatePassword() (string, error) {
	return password.Generate(64, 10, 0, false, true)
}

func normalizeAuthMountPath(path string) string {
	normalized := strings.Trim(path, "/")
	if normalized == "" {
		return "userpass"
	}

	return normalized
}

// entityName derives a run-unique, index-addressable entity name of the form
// mountName-entity-runID-idx.
func entityName(mountName, runID string, idx int) string {
	return mountName + "-entity-" + runID + "-" + strconv.Itoa(idx)
}

// selectGroupMembers returns groupSize entity ids for the given group index,
// walking the entity slice with wraparound so membership is deterministic.
func selectGroupMembers(entityIDs []string, groupIndex, groupSize int) []string {
	members := make([]string, 0, groupSize)
	start := (groupIndex * groupSize) % len(entityIDs)
	for offset := 0; offset < groupSize; offset++ {
		members = append(members, entityIDs[(start+offset)%len(entityIDs)])
	}
	return members
}

// identityIDFromResponse extracts the "id" field from an identity
// entity/group write or read response.
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

// sampleIndices returns k distinct 1-based indices in [1, n], chosen at random.
// It returns all indices when k >= n. Callers must pass 0 < k <= n.
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
