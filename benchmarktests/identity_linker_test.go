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

// fakeUserpass serves the minimal userpass surface validateLogin touches: login
// returns the response the test configures.
func fakeUserpass(t *testing.T, loginStatus int, loginBody string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/login/") {
			w.WriteHeader(loginStatus)
			if loginBody != "" {
				_, _ = w.Write([]byte(loginBody))
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
			server := fakeUserpass(t, tc.loginStatus, tc.loginBody)
			defer server.Close()

			client := newTestClient(t, server.URL)
			helper := &identityLinker{
				password:         "password-value",
				mountPath:        "userpass",
				userpassAccessor: "auth_userpass_00000000",
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

func TestResolveGroups(t *testing.T) {
	tests := []struct {
		name        string
		groups      *GroupConfig
		groupCount  int
		entityCount int
		wantFilled  int
		wantSize    int
		wantErr     bool
	}{
		{name: "no groups", groups: nil, groupCount: 0, entityCount: 100, wantFilled: 0, wantSize: 0},
		{name: "default is even", groups: nil, groupCount: 10, entityCount: 100, wantFilled: 10, wantSize: 10},
		{name: "even rounds up", groups: &GroupConfig{Preset: "even"}, groupCount: 7, entityCount: 100, wantFilled: 7, wantSize: 15},
		{name: "empty", groups: &GroupConfig{Preset: "empty"}, groupCount: 10, entityCount: 100, wantFilled: 0, wantSize: 0},
		{name: "max", groups: &GroupConfig{Preset: "max"}, groupCount: 10, entityCount: 100, wantFilled: 10, wantSize: 100},
		{name: "count+size partial", groups: &GroupConfig{Count: 5, Size: 20}, groupCount: 10, entityCount: 100, wantFilled: 5, wantSize: 20},
		{name: "invalid preset", groups: &GroupConfig{Preset: "bogus"}, groupCount: 10, entityCount: 100, wantErr: true},
		{name: "count too high", groups: &GroupConfig{Count: 11, Size: 20}, groupCount: 10, entityCount: 100, wantErr: true},
		{name: "size too high", groups: &GroupConfig{Count: 5, Size: 200}, groupCount: 10, entityCount: 100, wantErr: true},
		{name: "preset and count conflict", groups: &GroupConfig{Preset: "even", Count: 5}, groupCount: 10, entityCount: 100, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filled, size, err := resolveGroups(tc.groups, tc.groupCount, tc.entityCount)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got filled=%d size=%d", filled, size)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filled != tc.wantFilled || size != tc.wantSize {
				t.Fatalf("got filled=%d size=%d, want filled=%d size=%d", filled, size, tc.wantFilled, tc.wantSize)
			}
		})
	}
}
