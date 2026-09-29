// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
)

// generateUUID is a thin wrapper so callers don't need to import go-uuid directly.
func generateUUID() (string, error) {
	return uuid.GenerateUUID()
}

const (
	scimPolicyName   = "scim-bench-policy"
	scimMountBase    = "userpass"
	scimUserPassword = "scim-bench-pw"

	// scimUserSchemaCore is the SCIM 2.0 User schema ID.
	scimUserSchemaCore  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchemaCore = "urn:ietf:params:scim:schemas:core:2.0:Group"

	// scimFilterSeedUserToken and scimFilterSeedGroupToken may appear inside a
	// user_list/group_list filter string. Setup() substitutes them with the
	// actual name of a pre-seeded resource (seed_user_count/seed_group_count)
	// so a "point lookup" filter is guaranteed to match real, runID-scoped data
	// instead of a hardcoded literal that can never match.
	scimFilterSeedUserToken  = "$SEED_USERNAME"
	scimFilterSeedGroupToken = "$SEED_GROUPNAME"
)

// scimClientPolicy is the minimum ACL policy a SCIM client token needs.
const scimClientPolicy = `
path "identity/scim/v2/Users" {
  capabilities = ["create","read","update","patch","delete","list"]
}
path "identity/scim/v2/Users/*" {
  capabilities = ["create","read","update","patch","delete","list"]
}
path "identity/scim/v2/Groups" {
  capabilities = ["create","read","update","patch","delete","list"]
}
path "identity/scim/v2/Groups/*" {
  capabilities = ["create","read","update","patch","delete","list"]
}
path "identity/scim/v2/ResourceTypes" { capabilities = ["read"] }
path "identity/scim/v2/ResourceTypes/*" { capabilities = ["read"] }
path "identity/scim/v2/Schemas" { capabilities = ["read"] }
path "identity/scim/v2/Schemas/*" { capabilities = ["read"] }
path "identity/scim/v2/ServiceProviderConfig" { capabilities = ["read"] }
path "identity/scim/client" {
  capabilities = ["create","read","update","delete","list","patch"]
}
path "identity/scim/client/*" {
  capabilities = ["create","read","update","delete","list","patch"]
}
`

// ── Shared SCIM client singleton ─────────────────────────────────────────────
//
// All scim_users and scim_groups test blocks in a single benchmark run share
// one SCIM client. This mirrors a real IdP: a single Entra/Okta tenant has one
// SCIM provisioning credential, not one per operation type.
//
// Sharing also fixes a correctness problem: when each block owns its own client,
// concurrent cleanup calls race — one block's delete-linked-resources=true can
// interfere with another block's per-resource SCIM DELETE, producing
// "managed by a different SCIM client" 403s.
//
// Implementation: a package-level map protected by a mutex. The first Setup()
// call creates the client; all subsequent ones reuse it. A reference counter
// tracks how many test blocks are using the shared instance. The last Cleanup()
// call (refCount reaching zero) performs the actual Vault teardown.

// scimSharedClient holds the state shared across all test blocks in one run.
type scimSharedClient struct {
	runID              string
	scimToken          string
	aliasMountAccessor string
	namespace          string
	refCount           int // number of test blocks currently holding this instance

	// adoptUserNames / adoptGroupIDs accumulate every name seeded by user_adopt /
	// group_adopt blocks sharing this client. Only the subset actually adopted
	// during the attack gets removed by delete-linked-resources; the last
	// Cleanup() sweeps whatever remains in these lists (see scimReleaseSharedClient).
	adoptUserNames []string
	adoptGroupIDs  []string
}

var (
	scimSharedMu      sync.Mutex
	scimSharedClients = map[string]*scimSharedClient{} // key = sharedKey
)

// scimSharedKey returns the map key used to look up the shared client.
// We derive it from the admin client's address + namespace so that different
// clusters in the same process (e.g. parallel test suites) get distinct clients.
func scimSharedKey(client *api.Client) string {
	ns := client.Headers().Get("X-Vault-Namespace")
	return client.Address() + "|" + ns
}

// scimAcquireSharedClient returns the shared SCIM client for this cluster,
// creating it if this is the first caller. The caller must eventually call
// scimReleaseSharedClient to decrement the reference count.
//
// The singleton is keyed by address+namespace (one client per cluster per
// process), but uses a fresh UUID as the runID each time a new singleton is
// created. The UUID scopes all Vault object names (entities, groups, mounts,
// policies) so that:
//   - Different workload blocks within the same run share one client and one
//     runID — their name pools are disjoint because each block uses a
//     workload-specific prefix (scimCreateGroupDisplayName vs scimAdoptGroupName
//     vs scimCreateUserName, etc.).
//   - A new run always gets a new runID, so there are no name collisions with
//     any state a previous run may have left behind on a persistent cluster.
func scimAcquireSharedClient(client *api.Client) (*scimSharedClient, error) {
	key := scimSharedKey(client)

	scimSharedMu.Lock()
	defer scimSharedMu.Unlock()

	if sc, ok := scimSharedClients[key]; ok {
		sc.refCount++
		return sc, nil
	}

	// First caller for this cluster in this process — generate a fresh runID
	// and create the Vault objects.
	runID, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("scim shared client: generating run ID: %w", err)
	}
	ns := client.Headers().Get("X-Vault-Namespace")

	scimToken, accessor, err := SCIMClientSetup(client, runID, true, true)
	if err != nil {
		return nil, fmt.Errorf("scim shared client setup: %w", err)
	}

	sc := &scimSharedClient{
		runID:              runID,
		scimToken:          scimToken,
		aliasMountAccessor: accessor,
		namespace:          ns,
		refCount:           1,
	}
	scimSharedClients[key] = sc
	return sc, nil
}

// scimReleaseSharedClient decrements the reference count for the shared client.
// When the count reaches zero it tears down all Vault objects created by
// scimAcquireSharedClient.
func scimReleaseSharedClient(client *api.Client) error {
	key := scimSharedKey(client)

	scimSharedMu.Lock()
	sc, ok := scimSharedClients[key]
	if !ok {
		// Already cleaned up or never created — nothing to do.
		scimSharedMu.Unlock()
		return nil
	}

	sc.refCount--
	if sc.refCount > 0 {
		scimSharedMu.Unlock()
		return nil
	}

	// Last holder — tear down. Copy out what the sweep needs before unlocking;
	// nothing else can reach this *scimSharedClient after the map delete.
	delete(scimSharedClients, key)
	runID := sc.runID
	adoptUserNames := sc.adoptUserNames
	adoptGroupIDs := sc.adoptGroupIDs
	scimSharedMu.Unlock()

	var errs []error
	if err := SCIMCleanup(client, runID); err != nil {
		errs = append(errs, err)
	}

	// SCIMCleanup's delete-linked-resources=true already removed every entity/group
	// that WAS adopted during the run. Anything from the seed pools still present
	// at this point was never adopted, so it's safe to delete directly.
	if err := sweepUnadoptedEntities(client, adoptUserNames); err != nil {
		errs = append(errs, err)
	}
	if err := sweepUnadoptedGroups(client, adoptGroupIDs); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// sweepUnadoptedEntities deletes any entity in names that Vault still has.
// Deleting an already-gone entity by name is a documented no-op (no error), so
// this is safe to call unconditionally against the full user_adopt seed pool.
func sweepUnadoptedEntities(client *api.Client, names []string) error {
	return deletePhase(targetLogger, "sweep unadopted seed entities", client, "identity/entity/name/", identityConcurrency, len(names), func(idx int) string {
		return names[idx]
	})
}

// sweepUnadoptedGroups deletes any group in ids that Vault still has.
// Deleting an already-gone group by ID is a documented no-op (no error), so
// this is safe to call unconditionally against the full group_adopt seed pool.
func sweepUnadoptedGroups(client *api.Client, ids []string) error {
	return deletePhase(targetLogger, "sweep unadopted seed groups", client, "identity/group/id/", identityConcurrency, len(ids), func(idx int) string {
		return ids[idx]
	})
}

// ── Name helpers ──────────────────────────────────────────────────────────────

// scimMountPath returns the userpass mount path for a given runID.
func scimMountPath(runID string) string {
	return scimMountBase + "-scim-" + runID
}

// scimClientName returns the SCIM client config name for a given runID.
func scimClientName(runID string) string {
	return "bench-scim-client-" + runID
}

// scimClientEntityName returns the deterministic Vault entity name for the SCIM
// client itself (the entity that holds the access_grant_principal).
func scimClientEntityName(runID string) string {
	return "bench-scim-entity-" + runID
}

// scimClientAliasName returns the username used for the userpass alias of the SCIM
// client — this is the identity that logs in to get the SCIM token.
func scimClientAliasName(runID string) string {
	return "bench-scim-alias-" + runID
}

// scimAdoptUserAliasName returns the alias name (== SCIM userName) for the
// i-th pre-seeded adoption target entity.  Must be distinct from the entity
// name (scimAdoptEntityName), mirroring how real IdP-created logins work:
//
//	entity name  = "bench-adopt-entity-<runID>-<i>"  (internal Vault name)
//	alias name   = "bench-adopt-user-<runID>-<i>@example.com"  (IdP identity)
func scimAdoptUserAliasName(runID string, i int) string {
	return "bench-adopt-user-" + runID + "-" + strconv.Itoa(i) + "@example.com"
}

// scimAdoptEntityName returns the internal Vault entity name for the i-th
// pre-seeded adoption target. Intentionally differs from the alias name.
func scimAdoptEntityName(runID string, i int) string {
	return "bench-adopt-entity-" + runID + "-" + strconv.Itoa(i)
}

// scimAdoptGroupName returns the Vault group name for the i-th pre-seeded
// adoption target group.  Group adoption matches on displayName == Vault group
// name, so the name IS also used as the SCIM displayName in the PUT body.
func scimAdoptGroupName(runID string, i int) string {
	return "bench-adopt-group-" + runID + "-" + strconv.Itoa(i)
}

// scimCreateUserName returns the SCIM userName for the i-th freshly-created
// user in the given scope. scope differentiates pools that share the same runID
// but must not collide — e.g. "uc" for user_create vs "gm" for group members
// seeded by group_create.
func scimCreateUserName(runID, scope string, i int) string {
	return "bench-create-user-" + scope + "-" + runID + "-" + strconv.Itoa(i) + "@example.com"
}

// scimCreateGroupDisplayName returns the SCIM displayName for the i-th
// freshly-created group in the given scope. scope differentiates pools that
// share the same runID — e.g. "gc" for group_create vs "ge" for group_create_empty.
func scimCreateGroupDisplayName(runID, scope string, i int) string {
	return "bench-create-group-" + scope + "-" + runID + "-" + strconv.Itoa(i)
}

// ── Vault provisioning ────────────────────────────────────────────────────────

// SCIMClientSetup provisions all the Vault objects the SCIM client needs:
//
//  1. ACL policy (scimClientPolicy)
//  2. Userpass auth mount scoped to this run
//  3. A Vault entity (access_grant_principal) with the policy attached
//  4. A userpass alias + credential so the entity can log in
//  5. The identity/scim/client config
//
// Returns the SCIM client token (already authenticated as the SCIM entity)
// and the userpass mount accessor (needed to create adoption-target aliases).
// Must be called with an admin/root token.
func SCIMClientSetup(client *api.Client, runID string, allowUserAdoption, allowGroupAdoption bool) (scimToken, aliasMountAccessor string, err error) {
	policyName := scimPolicyName + "-" + runID
	if err = client.Sys().PutPolicy(policyName, scimClientPolicy); err != nil {
		return "", "", fmt.Errorf("scim setup: writing policy %q: %w", policyName, err)
	}

	mountPath := scimMountPath(runID)
	if err = client.Sys().EnableAuthWithOptions(mountPath, &api.EnableAuthOptions{
		Type: "userpass",
		Config: api.AuthConfigInput{
			TokenType: "service",
		},
	}); err != nil {
		return "", "", fmt.Errorf("scim setup: enabling userpass mount %q: %w", mountPath, err)
	}

	mounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", "", fmt.Errorf("scim setup: listing auth mounts: %w", err)
	}
	mount, ok := mounts[mountPath+"/"]
	if !ok {
		return "", "", fmt.Errorf("scim setup: auth mount %q not found after enable", mountPath)
	}
	aliasMountAccessor = mount.Accessor

	// Create the SCIM client entity.
	entityResp, err := client.Logical().Write("identity/entity", map[string]any{
		"name":     scimClientEntityName(runID),
		"policies": []string{policyName},
	})
	if err != nil {
		return "", "", fmt.Errorf("scim setup: creating SCIM client entity: %w", err)
	}
	entityID, err := idFromResponse(entityResp)
	if err != nil {
		return "", "", fmt.Errorf("scim setup: reading SCIM client entity id: %w", err)
	}

	// Create userpass alias + credential so the entity can authenticate.
	aliasName := scimClientAliasName(runID)
	if _, err = client.Logical().Write("identity/entity-alias", map[string]any{
		"name":           aliasName,
		"canonical_id":   entityID,
		"mount_accessor": aliasMountAccessor,
	}); err != nil {
		return "", "", fmt.Errorf("scim setup: creating SCIM client entity-alias: %w", err)
	}
	userPath := filepath.ToSlash(filepath.Join("auth", mountPath, "users", aliasName))
	if _, err = client.Logical().Write(userPath, map[string]any{
		"password": scimUserPassword,
	}); err != nil {
		return "", "", fmt.Errorf("scim setup: creating userpass user %q: %w", aliasName, err)
	}

	// Register the SCIM client config.
	clientCfg := map[string]any{
		"access_grant_principal": entityID,
		"allow_user_adoption":    allowUserAdoption,
		"allow_group_adoption":   allowGroupAdoption,
		"alias_mount_accessor":   aliasMountAccessor,
	}
	if _, err = client.Logical().Write("identity/scim/client/"+scimClientName(runID), clientCfg); err != nil {
		return "", "", fmt.Errorf("scim setup: writing scim/client config: %w", err)
	}

	// Log in as the SCIM client and return its token.
	loginPath := filepath.ToSlash(filepath.Join("auth", mountPath, "login", aliasName))
	loginResp, err := client.Logical().Write(loginPath, map[string]any{
		"password": scimUserPassword,
	})
	if err != nil {
		return "", "", fmt.Errorf("scim setup: logging in as SCIM client: %w", err)
	}
	if loginResp == nil || loginResp.Auth == nil || loginResp.Auth.ClientToken == "" {
		return "", "", fmt.Errorf("scim setup: login returned no token")
	}

	return loginResp.Auth.ClientToken, aliasMountAccessor, nil
}

// SCIMCleanup removes all objects created by SCIMClientSetup (policy, userpass
// mount, entity, scim client config). Call with admin/root token.
//
// The SCIM client is deleted with delete-linked-resources=true so that any
// resources still owned by it (e.g. users/groups created during the run but not
// individually deleted beforehand) are removed atomically by Vault.
func SCIMCleanup(client *api.Client, runID string) error {
	var errs []string

	// delete-linked-resources=true instructs Vault to remove all SCIM-owned
	// entities and groups before deleting the client record.  A plain DELETE
	// returns HTTP 400 "SCIM client has linked resources" whenever the benchmark
	// has created any users/groups during the run.
	// The Vault Go SDK does not expose query-param DELETE, so we use a raw HTTP
	// request — the same pattern used in DebugInfo and seedSCIMUsers.
	if err := scimClientDeleteWithLinkedResources(client, scimClientName(runID)); err != nil {
		errs = append(errs, fmt.Sprintf("delete scim client: %v", err))
	}
	if _, err := client.Logical().Delete("identity/entity/name/" + scimClientEntityName(runID)); err != nil {
		errs = append(errs, fmt.Sprintf("delete scim entity: %v", err))
	}
	if err := client.Sys().DisableAuth(scimMountPath(runID)); err != nil {
		errs = append(errs, fmt.Sprintf("disable userpass mount: %v", err))
	}
	if err := client.Sys().DeletePolicy(scimPolicyName + "-" + runID); err != nil {
		errs = append(errs, fmt.Sprintf("delete policy: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("scim cleanup errors: %v", errs)
	}
	return nil
}

// scimClientDeleteWithLinkedResources sends:
//
//	DELETE /v1/identity/scim/client/<name>?delete-linked-resources=true
//
// using the admin token on client. The SDK's Logical().Delete() does not
// support query parameters, so we build a raw HTTP request instead.
func scimClientDeleteWithLinkedResources(client *api.Client, clientName string) error {
	url := client.Address() + "/v1/identity/scim/client/" + clientName + "?delete-linked-resources=true"
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewReader(nil))
	if err != nil {
		return fmt.Errorf("building DELETE request for scim client %q: %w", clientName, err)
	}
	req.Header.Set("X-Vault-Token", client.Token())
	ns := client.Headers().Get("X-Vault-Namespace")
	if ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	resp, err := client.CloneConfig().HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE scim client %q: %w", clientName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE scim client %q: unexpected status %d: %s", clientName, resp.StatusCode, body)
	}
	return nil
}

// scimDeleteViaSCIMAPI deletes a single SCIM resource (User or Group) by ID
// using the SCIM token. This is required for resources that are already
// SCIM-managed: the admin identity API returns 403/500 for those.
// resourceType must be "Users" or "Groups".
func scimDeleteViaSCIMAPI(client *api.Client, scimToken, namespace, resourceType, resourceID string) error {
	url := client.Address() + "/v1/identity/scim/v2/" + resourceType + "/" + resourceID
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewReader(nil))
	if err != nil {
		return fmt.Errorf("building DELETE request for %s/%s: %w", resourceType, resourceID, err)
	}
	for k, vals := range scimHeader(scimToken, namespace) {
		for _, v := range vals {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.CloneConfig().HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s/%s: %w", resourceType, resourceID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE %s/%s: unexpected status %d: %s", resourceType, resourceID, resp.StatusCode, body)
	}
	return nil
}

// scimDeletePhase bulk-deletes SCIM resources using the SCIM token (required
// for SCIM-owned entities/groups that the admin identity API refuses to delete).
func scimDeletePhase(logger hclog.Logger, phase, resourceType string, client *api.Client, scimToken, namespace string, ids []string) error {
	return runPhase(logger, phase, identityConcurrency, len(ids), func(i int) error {
		return scimDeleteViaSCIMAPI(client, scimToken, namespace, resourceType, ids[i])
	})
}

// scimHeader returns the HTTP headers for SCIM requests: Vault token + namespace.
func scimHeader(token, namespace string) http.Header {
	h := http.Header{
		"X-Vault-Token": []string{token},
		"Content-Type":  []string{"application/json"},
	}
	if namespace != "" {
		h["X-Vault-Namespace"] = []string{namespace}
	}
	return h
}

// debugLogSCIMResponse reads the body of a raw *api.Response, logs it at DEBUG
// level, and returns the status code and raw body for the caller to assert on.
// The body is consumed and the response is closed.
func debugLogSCIMResponse(resp *http.Response) (statusCode int, body []byte) {
	if resp == nil {
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// ── SCIM request body builders ────────────────────────────────────────────────

// scimUserCreateBody returns the JSON body for a SCIM POST /Users (creation).
func scimUserCreateBody(userName, externalID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"schemas":    []string{scimUserSchemaCore},
		"userName":   userName,
		"externalId": externalID,
		"active":     true,
	})
	return b
}

// scimUserAdoptBody returns the JSON body for a SCIM POST /Users (adoption).
// userName must match an existing unmanaged alias name on the SCIM client's
// alias_mount_accessor mount.
func scimUserAdoptBody(userName, externalID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"schemas":    []string{scimUserSchemaCore},
		"userName":   userName,
		"externalId": externalID,
		"active":     true,
	})
	return b
}

// scimGroupCreateBody returns the JSON body for a SCIM POST /Groups (creation).
// members is a slice of Vault entity IDs that are already SCIM-owned.
func scimGroupCreateBody(displayName string, memberIDs []string) []byte {
	members := make([]map[string]string, len(memberIDs))
	for i, id := range memberIDs {
		members[i] = map[string]string{"value": id}
	}
	b, _ := json.Marshal(map[string]any{
		"schemas":     []string{scimGroupSchemaCore},
		"displayName": displayName,
		"members":     members,
	})
	return b
}

// scimGroupAdoptBody returns the JSON body for a SCIM PUT /Groups/<id> (adoption).
// displayName must match the Vault group's name exactly.
func scimGroupAdoptBody(displayName string) []byte {
	b, _ := json.Marshal(map[string]any{
		"schemas":     []string{scimGroupSchemaCore},
		"displayName": displayName,
	})
	return b
}

// seedSCIMUsers creates SCIM-owned users via the SCIM API and returns their
// Vault entity IDs. scope keeps name pools distinct across callers that share
// a runID — e.g. "gm" for group members seeded by group_create, "lf" for
// list-filter seed data seeded by user_list.
func seedSCIMUsers(logger hclog.Logger, adminClient *api.Client, scimToken, runID, scope, namespace string, count int) ([]string, error) {
	entityIDs := make([]string, count)
	header := scimHeader(scimToken, namespace)

	err := runPhase(logger, "seed scim users", identityConcurrency, count, func(i int) error {
		userName := scimCreateUserName(runID, scope, i)
		externalID := "seed-ext-" + userName
		body := scimUserCreateBody(userName, externalID)

		req, err := http.NewRequest(http.MethodPost,
			adminClient.Address()+"/v1/identity/scim/v2/Users",
			bytes.NewReader(body),
		)
		if err != nil {
			return fmt.Errorf("building seed user request %d: %w", i, err)
		}
		for k, vals := range header {
			for _, v := range vals {
				req.Header.Set(k, v)
			}
		}

		resp, err := adminClient.CloneConfig().HttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("posting seed user %d: %w", i, err)
		}
		statusCode, respBody := debugLogSCIMResponse(resp)
		logger.Debug("seed scim user response",
			"index", i, "user_name", userName, "status", statusCode, "body", string(respBody),
		)
		if statusCode != http.StatusCreated {
			return fmt.Errorf("seed user %d (%q): unexpected status %d, body: %s", i, userName, statusCode, respBody)
		}

		var parsed map[string]any
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("parsing seed user response %d: %w", i, err)
		}
		id, ok := parsed["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("seed user response %d missing id field", i)
		}
		entityIDs[i] = id
		return nil
	}, "total", count)

	return entityIDs, err
}

// seedSCIMGroups creates SCIM-owned groups (no members) via the SCIM API.
// Used to give group_list filter tests real, findable data to query against.
// scope keeps this pool distinct from other group name pools sharing the runID.
func seedSCIMGroups(logger hclog.Logger, adminClient *api.Client, scimToken, runID, scope, namespace string, count int) error {
	header := scimHeader(scimToken, namespace)

	return runPhase(logger, "seed scim groups", identityConcurrency, count, func(i int) error {
		displayName := scimCreateGroupDisplayName(runID, scope, i)
		body := scimGroupCreateBody(displayName, nil)

		req, err := http.NewRequest(http.MethodPost,
			adminClient.Address()+"/v1/identity/scim/v2/Groups",
			bytes.NewReader(body),
		)
		if err != nil {
			return fmt.Errorf("building seed group request %d: %w", i, err)
		}
		for k, vals := range header {
			for _, v := range vals {
				req.Header.Set(k, v)
			}
		}

		resp, err := adminClient.CloneConfig().HttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("posting seed group %d: %w", i, err)
		}
		statusCode, respBody := debugLogSCIMResponse(resp)
		logger.Debug("seed scim group response",
			"index", i, "display_name", displayName, "status", statusCode, "body", string(respBody),
		)
		if statusCode != http.StatusCreated {
			return fmt.Errorf("seed group %d (%q): unexpected status %d, body: %s", i, displayName, statusCode, respBody)
		}
		return nil
	}, "total", count)
}
