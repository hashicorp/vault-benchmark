// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/vault/api"
)

func TestTransformFPETest_Registered(t *testing.T) {
	builder, ok := TestList[TransformFPETestType]
	if !ok {
		t.Fatalf("expected %q to be registered", TransformFPETestType)
	}

	if _, ok := builder().(*TransformFPETest); !ok {
		t.Fatalf("expected registered builder to return *TransformFPETest")
	}
}

func TestTransformFPETest_ParseConfig(t *testing.T) {
	tAuth := TransformFPETest{}

	hclFile, diags := hclparse.NewParser().ParseHCLFile(filepath.Join(FixturePath, "secret_transform_fpe.hcl"))
	if diags != nil {
		t.Fatalf("err: %v", diags)
	}

	err := tAuth.ParseConfig(hclFile.Body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if tAuth.config == nil {
		t.Fatal("expected config to be populated")
	}

	if tAuth.config.RoleConfig.Name != "custom-role" {
		t.Fatalf("expected role name custom-role, got %q", tAuth.config.RoleConfig.Name)
	}

	if !reflect.DeepEqual(tAuth.config.RoleConfig.Transformations, []string{"custom-fpe"}) {
		t.Fatalf("unexpected role transformations: %#v", tAuth.config.RoleConfig.Transformations)
	}

	if tAuth.config.FPEConfig.Name != "custom-fpe" {
		t.Fatalf("expected FPE name custom-fpe, got %q", tAuth.config.FPEConfig.Name)
	}

	if tAuth.config.FPEConfig.Template != "custom-template" {
		t.Fatalf("expected template custom-template, got %q", tAuth.config.FPEConfig.Template)
	}

	if tAuth.config.FPEConfig.TweakSource != "supplied" {
		t.Fatalf("expected tweak source supplied, got %q", tAuth.config.FPEConfig.TweakSource)
	}

	if !reflect.DeepEqual(tAuth.config.FPEConfig.AllowedRoles, []string{"custom-role"}) {
		t.Fatalf("unexpected allowed roles: %#v", tAuth.config.FPEConfig.AllowedRoles)
	}

	if tAuth.config.InputConfig.Value != "1234-5678-9012-3456" {
		t.Fatalf("expected custom input value, got %q", tAuth.config.InputConfig.Value)
	}

	if tAuth.config.InputConfig.Transformation != "custom-fpe" {
		t.Fatalf("expected custom input transformation, got %q", tAuth.config.InputConfig.Transformation)
	}

	if tAuth.config.InputConfig.Tweak != "H0mSPAfSJg==" {
		t.Fatalf("expected custom tweak, got %q", tAuth.config.InputConfig.Tweak)
	}
}

func TestTransformFPETest_SetupTargetAndCleanup(t *testing.T) {
	targetLogger = hclog.NewNullLogger()

	type requestRecord struct {
		method string
		path   string
		body   map[string]interface{}
	}

	var mu sync.Mutex
	var handlerErr error
	var requests []requestRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		record := requestRecord{method: r.Method, path: r.URL.Path}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			handlerErr = fmt.Errorf("failed reading request body: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &record.body); err != nil {
				handlerErr = fmt.Errorf("failed decoding request body: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		mu.Lock()
		requests = append(requests, record)
		mu.Unlock()

		if r.URL.Path == "/v1/sys/mounts/fpe-test" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	client, err := api.NewClient(&api.Config{Address: server.URL, HttpClient: server.Client()})
	if err != nil {
		t.Fatalf("failed creating client: %v", err)
	}
	client.SetToken("root-token")
	client.SetNamespace("admin")

	tAuth := &TransformFPETest{}
	hclFile, diags := hclparse.NewParser().ParseHCLFile(filepath.Join(FixturePath, "secret_transform_fpe.hcl"))
	if diags != nil {
		t.Fatalf("err: %v", diags)
	}

	err = tAuth.ParseConfig(hclFile.Body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	builder, err := tAuth.Setup(client, "fpe-test", &TopLevelTargetConfig{RandomMounts: false})
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	fpeTest, ok := builder.(*TransformFPETest)
	if !ok {
		t.Fatalf("expected builder type *TransformFPETest, got %T", builder)
	}

	if fpeTest.pathPrefix != "/v1/fpe-test" {
		t.Fatalf("expected path prefix /v1/fpe-test, got %q", fpeTest.pathPrefix)
	}

	if fpeTest.roleName != "custom-role" {
		t.Fatalf("expected role name custom-role, got %q", fpeTest.roleName)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(fpeTest.body, &body); err != nil {
		t.Fatalf("failed to unmarshal target body: %v", err)
	}

	if body["value"] != "1234-5678-9012-3456" {
		t.Fatalf("expected request value to match config, got %#v", body["value"])
	}

	if body["transformation"] != "custom-fpe" {
		t.Fatalf("expected transformation to match config, got %#v", body["transformation"])
	}

	if body["tweak"] != "H0mSPAfSJg==" {
		t.Fatalf("expected tweak to match config, got %#v", body["tweak"])
	}

	target := fpeTest.Target(client)
	if target.Method != TransformFPETestMethod {
		t.Fatalf("expected target method %q, got %q", TransformFPETestMethod, target.Method)
	}

	if target.URL != server.URL+"/v1/fpe-test/encode/custom-role" {
		t.Fatalf("unexpected target URL: %q", target.URL)
	}

	if got := target.Header.Get("X-Vault-Token"); got != "root-token" {
		t.Fatalf("expected X-Vault-Token header to be set, got %q", got)
	}

	if got := target.Header.Get("X-Vault-Namespace"); got != "admin" {
		t.Fatalf("expected X-Vault-Namespace header to be set, got %q", got)
	}

	err = fpeTest.Cleanup(client)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	if handlerErr != nil {
		t.Fatalf("handler error: %v", handlerErr)
	}

	if len(requests) != 5 {
		t.Fatalf("expected 5 requests during setup and cleanup, got %d", len(requests))
	}

	assertRequestPath(t, requests[0], http.MethodPost, "/v1/sys/mounts/fpe-test")
	assertRequestPath(t, requests[1], http.MethodPut, "/v1/fpe-test/template/custom-template")
	assertRequestPath(t, requests[2], http.MethodPut, "/v1/fpe-test/transformations/fpe/custom-fpe")
	assertRequestPath(t, requests[3], http.MethodPut, "/v1/fpe-test/role/custom-role")
	assertRequestPath(t, requests[4], http.MethodDelete, "/v1/sys/mounts/fpe-test")

	if requests[1].body["type"] != "regex" {
		t.Fatalf("expected template type regex, got %#v", requests[1].body["type"])
	}

	if requests[2].body["template"] != "custom-template" {
		t.Fatalf("expected transformation template custom-template, got %#v", requests[2].body["template"])
	}

	if requests[3].body["name"] != "custom-role" {
		t.Fatalf("expected role payload to include name custom-role, got %#v", requests[3].body["name"])
	}
}

func assertRequestPath(t *testing.T, request struct {
	method string
	path   string
	body   map[string]interface{}
}, method string, path string) {
	t.Helper()
	if request.method != method {
		t.Fatalf("expected method %q, got %q", method, request.method)
	}
	if request.path != path {
		t.Fatalf("expected path %q, got %q", path, request.path)
	}
}