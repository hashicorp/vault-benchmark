package benchmark_tests

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// TODO:
// genericTest interface will be for generic tests to cover anything new or
// more generic in nature that we can't easily put into and auth/secrets bucket
type GenericTest interface{}

type BenchmarkTarget interface {
	Target(client *api.Client) vegeta.Target
	Setup(client *api.Client, randomMountName bool, config interface{}) (BenchmarkTarget, error)
	Cleanup(client *api.Client) error
	ParseConfig(body hcl.Body) interface{}
	createTargetFraction() targetFraction
}
