// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/sethvargo/go-password/password"
)

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

	// Nothing to link unless aliases or users are requested.
	if !cfg.CreateAliases && !cfg.CreateUsers {
		return helper, nil
	}

	if helper.createUsers {
		generated, err := password.Generate(64, 10, 0, false, true)
		if err != nil {
			return nil, fmt.Errorf("error generating userpass password: %w", err)
		}
		helper.userPassword = generated
	}

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

// linkEntityAuth creates the entity alias and, when CreateUsers is set, the
// matching userpass user. The alias name and username are both the entity name.
func (h *identityAuthLinkHelper) linkEntityAuth(client *api.Client, name string, entityID string) error {
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

	if h.createUsers {
		userPath := filepath.ToSlash(filepath.Join("auth", h.userpassMountPath, "users", name))
		_, err := client.Logical().Write(userPath, map[string]any{
			"password": h.userPassword,
		})
		if err != nil {
			return fmt.Errorf("error creating userpass user %q: %w", name, err)
		}
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

func normalizeAuthMountPath(path string) string {
	normalized := strings.Trim(path, "/")
	if normalized == "" {
		return "userpass"
	}

	return normalized
}
