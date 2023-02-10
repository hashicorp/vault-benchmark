package benchmark_tests

import (
	"fmt"
	"io"
	"math/rand"
	"sort"

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

var TestList = make(map[string]func() BenchmarkBuilder)

type BenchmarkTarget struct {
	Builder    BenchmarkBuilder
	Target     vegeta.Target
	Remain     hcl.Body `hcl:",remain"`
	Name       string   `hcl:"name,label"`
	Type       string   `hcl:"type,label"`
	MountName  string   `hcl:"mount_name,optional"`
	Method     string
	PathPrefix string
	Weight     int `hcl:"weight,optional"`
}

type TargetInfo struct {
	method     string
	pathPrefix string
}

func (bt *BenchmarkTarget) ConfigureTarget(client *api.Client) {
	bt.Target = bt.Builder.Target(client)
	tInfo := bt.Builder.GetTargetInfo()
	bt.PathPrefix = tInfo.pathPrefix
	bt.Method = tInfo.method
}

// TargetMulti allows building a vegeta targetter that chooses between various
// operations randomly following a specified distribution.
type TargetMulti struct {
	targets []BenchmarkTarget
}

func (tm TargetMulti) validate() error {
	total := 0
	for _, bTest := range tm.targets {
		total += bTest.Weight
	}
	if total != 100 {
		return fmt.Errorf("test percentage total comes to %d, should be 100", total)
	}
	return nil
}

func (tm TargetMulti) choose(i int) *BenchmarkTarget {
	if i > 99 || i < 0 {
		panic("i must be between 0 and 99")
	}

	total := 0
	for _, target := range tm.targets {
		total += target.Weight
		if i < total {
			return &target
		}
	}

	panic("unreachable")
}

// TODO:
// Should probably spawn these as goroutines and use a
// waitgroup to help speed these up as this doesn't
// scale very well
func (tm TargetMulti) Cleanup(client *api.Client) error {
	for _, target := range tm.targets {
		currTargetBuilder := target.Builder
		if err := currTargetBuilder.Cleanup(client); err != nil {
			return err
		}
	}
	return nil
}

func (tm TargetMulti) Targeter(client *api.Client) (vegeta.Targeter, error) {
	if err := tm.validate(); err != nil {
		return nil, err
	}
	return func(tgt *vegeta.Target) error {
		if tgt == nil {
			return vegeta.ErrNilTarget
		}
		rnd := int(rand.Int31n(100))
		t := tm.choose(rnd)
		*tgt = t.Target
		return nil
	}, nil
}

func (tm TargetMulti) DebugInfo(client *api.Client) {
	for index, benchTarget := range tm.targets {
		fmt.Printf("Target %d: %v\n", index, benchTarget.Name)
		fmt.Printf("\tMethod: %v\n", benchTarget.Method)
		fmt.Printf("\tPath Prefix: %v\n", benchTarget.PathPrefix)
		target := benchTarget.Target
		req, err := target.Request()
		if err != nil {
			panic(fmt.Sprintf("Got err building target: %v", err))
		}
		fmt.Printf("\tRequest: %v\n", req)
		fmt.Printf("\tRequest Body: %v\n", string(target.Body))
		resp, err := client.CloneConfig().HttpClient.Do(req)
		if err != nil {
			panic(fmt.Sprintf("Got err executing target request: %v", err))
		}
		rawBody, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(fmt.Sprintf("Got err reading response body: %v", err))
		}
		fmt.Printf("\tResponse: %v\n", resp)
		fmt.Printf("\tResponse Body: %v\n", string(rawBody))
		if resp.StatusCode >= 400 {
			panic("Got error response from server on testing request; exiting")
		}
		fmt.Println()
	}
}

func BuildTargets(tests []*BenchmarkTarget, client *api.Client, caPEM string, clientCAPem string, randomMounts bool) (*TargetMulti, error) {
	var tm TargetMulti
	var err error

	for _, bvTest := range tests {
		mountName := bvTest.Name
		if bvTest.MountName != "" {
			mountName = bvTest.MountName
		}
		bvTest.Builder, err = bvTest.Builder.Setup(client, randomMounts, mountName)
		if err != nil {
			return nil, err
		}
		bvTest.ConfigureTarget(client)
		tm.targets = append(tm.targets, *bvTest)
	}

	// Put the biggest fractions first as an optimization
	sort.Slice(tm.targets, func(i, j int) bool {
		return tm.targets[j].Weight < tm.targets[i].Weight
	})

	err = tm.validate()
	if err != nil {
		return nil, err
	}
	return &tm, nil
}
