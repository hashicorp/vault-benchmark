// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"flag"
	"net/http"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	HAStatusTestType   = "ha_status"
	SealStatusTestType = "seal_status"
	MetricsTestType    = "metrics"
	StatusTestMethod   = "GET"
)

func init() {
	// "Register" this test to the main test registry
	TestList[HAStatusTestType] = func() BenchmarkBuilder { return &StatusCheck{pathPrefix: "ha-status"} }
	TestList[SealStatusTestType] = func() BenchmarkBuilder { return &StatusCheck{pathPrefix: "seal-status"} }
	TestList[MetricsTestType] = func() BenchmarkBuilder { return &StatusCheck{pathPrefix: "metrics"} }
}

type StatusCheck struct {
	pathPrefix string
	header     http.Header
}

func (s *StatusCheck) ParseConfig(body hcl.Body) error {
	return nil
}

func (s *StatusCheck) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var h http.Header
	switch s.pathPrefix {
	case "metrics":
		h = http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{"root"}}
	default:
		h = generateHeader(client)
	}
	return &StatusCheck{
		header:     h,
		pathPrefix: "/v1/sys/" + s.pathPrefix,
	}, nil
}

func (s *StatusCheck) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: StatusTestMethod,
		URL:    client.Address() + s.pathPrefix,
		Header: s.header,
	}
}

// Cleanup is a no-op for this test
func (s *StatusCheck) Cleanup(client *api.Client) error {
	return nil
}

func (s *StatusCheck) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     StatusTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *StatusCheck) Flags(fs *flag.FlagSet) {}
