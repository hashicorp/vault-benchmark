// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"net/http"
	"net/http/httptest"
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

func TestValidateLoginResolution(t *testing.T) {
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

// TestValidateLoginResolution_ProvisionsProbeUser covers the alias-only path
// (createUsers=false, as identity_group_read uses): a probe user must be
// created before the login check runs, using the helper's existing password.
func TestValidateLoginResolution_ProvisionsProbeUser(t *testing.T) {
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

// TestValidateLoginResolution_NoMount guards the fail-fast when no userpass
// mount was configured.
func TestValidateLoginResolution_NoMount(t *testing.T) {
	helper := &identityAuthLinkHelper{}
	err := helper.validateLogin(nil, "check-user", "entity-abc")
	if err == nil {
		t.Fatalf("expected error when no userpass mount is configured")
	}
	if !strings.Contains(err.Error(), "no userpass mount configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}
