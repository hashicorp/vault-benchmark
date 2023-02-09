package benchmark_tests

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type BenchmarkBuilder interface {
	// Target generates and returns a vegeta.Target struct which is used for the attack
	Target(client *api.Client) vegeta.Target

	// Setup uses the passed in client and configuration to create the necessary test resources
	// in Vault, and retrieve any necessary information needed to perform the test itself. Setup
	// returns a test struct type which satisfies this BenchmarkBuilder interface.
	Setup(client *api.Client, randomMountName bool, mountName string) (BenchmarkBuilder, error)

	// Cleanup uses the passed in client to clean up any created resources used as part of the test
	Cleanup(client *api.Client) error

	// ParseConfig accepts an hcl.Body struct and parses the config setting it as a field in the underlying
	// test struct
	ParseConfig(body hcl.Body)

	// GetTargetInfo retrieves specific Target information required to pass on to Attack
	GetTargetInfo() TargetInfo
}
