// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

// newTestClient returns a Vault API client pointed at addr with retries
// disabled so error responses surface immediately.
func newTestClient(t *testing.T, addr string) *api.Client {
	t.Helper()

	cfg := api.DefaultConfig()
	cfg.Address = addr
	cfg.MaxRetries = 0

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("error creating api client: %v", err)
	}
	client.SetToken("test-token")

	return client
}

// fakeUserpass serves the minimal userpass surface validateLogin
// touches: user creation returns 204, and login returns the response the test
// configures. It records whether the probe user was created.
func fakeUserpass(t *testing.T, loginStatus int, loginBody string, userCreated *bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/login/"):
			w.WriteHeader(loginStatus)
			if loginBody != "" {
				_, _ = w.Write([]byte(loginBody))
			}
		case strings.Contains(r.URL.Path, "/users/"):
			if userCreated != nil {
				*userCreated = true
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
}

func TestValidateLogin(t *testing.T) {
	const wantEntity = "entity-abc"

	tests := []struct {
		name        string
		loginStatus int
		loginBody   string
		wantErr     bool
		errContains string
	}{
		{
			name:        "resolves to expected entity",
			loginStatus: http.StatusOK,
			loginBody:   `{"auth":{"entity_id":"entity-abc","client_token":"t","policies":["default"]}}`,
			wantErr:     false,
		},
		{
			name:        "resolves to wrong entity",
			loginStatus: http.StatusOK,
			loginBody:   `{"auth":{"entity_id":"entity-wrong","client_token":"t","policies":["default"]}}`,
			wantErr:     true,
			errContains: "expected",
		},
		{
			name:        "login returns no auth data",
			loginStatus: http.StatusOK,
			loginBody:   `{"data":{}}`,
			wantErr:     true,
			errContains: "no auth data",
		},
		{
			name:        "login request fails",
			loginStatus: http.StatusInternalServerError,
			loginBody:   `{"errors":["boom"]}`,
			wantErr:     true,
			errContains: "login resolution check failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := fakeUserpass(t, tc.loginStatus, tc.loginBody, nil)
			defer server.Close()

			client := newTestClient(t, server.URL)
			helper := &identityAuthLinkHelper{
				createUsers:       true,
				userPassword:      "password-value",
				userpassMountPath: "userpass",
				userpassAccessor:  "auth_userpass_00000000",
			}

			err := helper.validateLogin(client, "check-user", wantEntity)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateLogin_ProvisionsProbeUser covers the alias-only path
// (createUsers=false, as identity_group_read uses): a probe user must be created
// before the login check, reusing the helper's password.
func TestValidateLogin_ProvisionsProbeUser(t *testing.T) {
	const wantEntity = "entity-abc"
	const wantPassword = "pre-generated-password"

	userCreated := false
	server := fakeUserpass(t, http.StatusOK,
		`{"auth":{"entity_id":"entity-abc","client_token":"t","policies":["default"]}}`, &userCreated)
	defer server.Close()

	client := newTestClient(t, server.URL)
	helper := &identityAuthLinkHelper{
		createUsers:       false,
		userPassword:      wantPassword,
		userpassMountPath: "userpass",
		userpassAccessor:  "auth_userpass_00000000",
	}

	if err := helper.validateLogin(client, "check-user", wantEntity); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !userCreated {
		t.Fatalf("expected a probe user to be created when createUsers is false")
	}
	if helper.userPassword != wantPassword {
		t.Fatalf("validate must not clobber the helper password: got %q, want %q", helper.userPassword, wantPassword)
	}
}

// TestValidateLogin_NoMount guards the fail-fast when no userpass mount exists.
func TestValidateLogin_NoMount(t *testing.T) {
	helper := &identityAuthLinkHelper{}
	err := helper.validateLogin(nil, "check-user", "entity-abc")
	if err == nil {
		t.Fatalf("expected error when no userpass mount is configured")
	}
	if !strings.Contains(err.Error(), "no userpass mount configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSampleIndices(t *testing.T) {
	t.Run("returns k distinct in-range indices", func(t *testing.T) {
		const n, k = 1000, 50
		idxs := sampleIndices(n, k)
		if len(idxs) != k {
			t.Fatalf("got %d indices, want %d", len(idxs), k)
		}

		seen := make(map[int]struct{}, len(idxs))
		for _, idx := range idxs {
			if idx < 1 || idx > n {
				t.Fatalf("index %d out of range [1, %d]", idx, n)
			}
			if _, dup := seen[idx]; dup {
				t.Fatalf("duplicate index %d", idx)
			}
			seen[idx] = struct{}{}
		}
	})

	t.Run("returns all indices when k >= n", func(t *testing.T) {
		const n = 5
		for _, k := range []int{n, n + 3} {
			idxs := sampleIndices(n, k)
			if len(idxs) != n {
				t.Fatalf("k=%d: got %d indices, want %d", k, len(idxs), n)
			}
			for want, got := range idxs {
				if got != want+1 {
					t.Fatalf("k=%d: index[%d]=%d, want %d", k, want, got, want+1)
				}
			}
		}
	})

	t.Run("varies across calls and covers the range", func(t *testing.T) {
		// The checks above pass even for a fixed [1..k] result, so confirm the
		// sample is actually random: results must differ between calls and reach
		// beyond the first k into the upper range.
		const n, k = 1000, 50
		baseline := sampleIndices(n, k)
		varied, reachedUpperRange := false, false
		for trial := 0; trial < 10; trial++ {
			got := sampleIndices(n, k)
			if !slices.Equal(got, baseline) {
				varied = true
			}
			for _, idx := range got {
				if idx > n/2 {
					reachedUpperRange = true
				}
			}
		}
		if !varied {
			t.Fatal("identical results across calls; not sampling randomly")
		}
		if !reachedUpperRange {
			t.Fatalf("no index above %d across trials; not sampling across the range", n/2)
		}
	})
}
