// Copyright IBM Corp. 2022, 2026
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
	TestList[HAStatusTestType] = func() BenchmarkBuilder { return &SysStatus{pathPrefix: "ha-status"} }
	TestList[SealStatusTestType] = func() BenchmarkBuilder { return &SysStatus{pathPrefix: "seal-status"} }
	TestList[MetricsTestType] = func() BenchmarkBuilder { return &SysStatus{pathPrefix: "metrics"} }
}

type SysStatus struct {
	pathPrefix string
	header     http.Header
}

func (s *SysStatus) ParseConfig(body hcl.Body) error {
	return nil
}

func (s *SysStatus) Setup(client *api.Client, mountName string, topLevelConfig *TopLevelTargetConfig) (BenchmarkBuilder, error) {
	var h http.Header
	switch s.pathPrefix {
	case "metrics":
		h = http.Header{"X-Vault-Token": []string{client.Token()}, "X-Vault-Namespace": []string{"root"}}
	default:
		h = generateHeader(client)
	}
	return &SysStatus{
		header:     h,
		pathPrefix: "/v1/sys/" + s.pathPrefix,
	}, nil
}

func (s *SysStatus) Target(client *api.Client) vegeta.Target {
	return vegeta.Target{
		Method: StatusTestMethod,
		URL:    client.Address() + s.pathPrefix,
		Header: s.header,
	}
}

func (s *SysStatus) Cleanup(client *api.Client) error {
	return nil
}

func (s *SysStatus) GetTargetInfo() TargetInfo {
	return TargetInfo{
		method:     StatusTestMethod,
		pathPrefix: s.pathPrefix,
	}
}

func (s *SysStatus) Flags(fs *flag.FlagSet) {}
