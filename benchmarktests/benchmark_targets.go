package benchmarktests

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"sort"

	"github.com/hashicorp/go-hclog"
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

	// ParseConfig accepts an hcl.Body and parses it into the underlying test struct
	ParseConfig(body hcl.Body) error

	// GetTargetInfo retrieves specific Target information required to pass on to Attack
	GetTargetInfo() TargetInfo

	// Flags allows tests to define flags in the passed in command flag set
	Flags(fs *flag.FlagSet)
}

var (
	TestList     = make(map[string]func() BenchmarkBuilder)
	targetLogger hclog.Logger
)

type BenchmarkTarget struct {
	Builder    BenchmarkBuilder
	Target     func(*api.Client) vegeta.Target
	Remain     hcl.Body `hcl:",remain"`
	Type       string   `hcl:"type,label"`
	Name       string   `hcl:"name,label"`
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
	bt.Target = bt.Builder.Target
	tInfo := bt.Builder.GetTargetInfo()
	bt.PathPrefix = tInfo.pathPrefix
	bt.Method = tInfo.method
}

// TargetMulti allows building a vegeta targetter that chooses between various
// operations randomly following a specified distribution.
type TargetMulti struct {
	targets []BenchmarkTarget
}

func (tm TargetMulti) choose(i int) *BenchmarkTarget {
	if i > 99 || i < 0 {
		log.Fatalf("i must be between 0 and 99")
	}

	total := 0
	for _, target := range tm.targets {
		total += target.Weight
		if i < total {
			return &target
		}
	}

	log.Fatalf("unreachable")
	return nil
}

// TODO:
// Should probably spawn these as goroutines and use a
// waitgroup to help speed these up as this doesn't
// scale very well
func (tm TargetMulti) Cleanup(client *api.Client) error {
	for _, target := range tm.targets {
		targetLogger.Debug("cleaning up target", "target", hclog.Fmt("%v", target.Name))
		if err := target.Builder.Cleanup(client); err != nil {
			return err
		}
	}
	return nil
}

func (tm TargetMulti) Targeter(client *api.Client) (vegeta.Targeter, error) {
	return func(tgt *vegeta.Target) error {
		if tgt == nil {
			return vegeta.ErrNilTarget
		}
		rnd := int(rand.Int31n(100))
		t := tm.choose(rnd)
		*tgt = t.Target(client)
		return nil
	}, nil
}

func (tm TargetMulti) DebugInfo(client *api.Client) {
	for index, benchTarget := range tm.targets {
		targetDebugInfo := fmt.Sprintf("\nTarget %d: %v\n", index, benchTarget.Name) +
			fmt.Sprintf("\tMethod: %v\n", benchTarget.Method) +
			fmt.Sprintf("\tPath Prefix: %v\n", benchTarget.PathPrefix)

		target := benchTarget.Target(client)
		req, err := target.Request()
		if err != nil {
			targetLogger.Error(fmt.Sprintf("Got err building target: %v", err))
			os.Exit(1)
		}
		targetLogger.Debug(targetDebugInfo + fmt.Sprintf("\tRequest: %v", req.URL.String()))

		resp, err := client.CloneConfig().HttpClient.Do(req)
		if err != nil {
			targetLogger.Error(fmt.Sprintf("Got err executing target request: %v", err))
			os.Exit(1)
		}
		rawBody, err := io.ReadAll(resp.Body)
		if err != nil {
			targetLogger.Debug(fmt.Sprintf("Got err reading response body: %v", err))
			os.Exit(1)
		}
		targetLogger.Debug(targetDebugInfo + fmt.Sprintf("\tResponse: %v\n", resp) +
			fmt.Sprintf("\tResponse Body: %v", string(rawBody)))
		if resp.StatusCode >= 400 {
			targetLogger.Debug("Got error response from server on testing request; exiting")
			os.Exit(1)
		}
	}
}

func BuildTargets(tests []*BenchmarkTarget, client *api.Client, logger hclog.Logger, string, clientCAPem string, randomMounts bool) (*TargetMulti, error) {
	var tm TargetMulti
	var err error
	targetLogger = logger

	// Check to make sure all weights add to 100
	err = percentageValidate(tests)
	if err != nil {
		return nil, err
	}

	// Build tests
	for _, bvTest := range tests {
		targetLogger.Debug("setting up target", "target", hclog.Fmt("%v", bvTest.Name))
		mountName := bvTest.Name
		if bvTest.MountName != "" {
			mountName = bvTest.MountName
		}
		bvTest.Builder, err = bvTest.Builder.Setup(client, randomMounts, mountName)
		if err != nil {
			// TODO:
			// We should look to implement some mechanism to clean up the mount if we
			// fail to configure some aspect of it (config, role, etc.)
			return nil, err
		}
		bvTest.ConfigureTarget(client)
		tm.targets = append(tm.targets, *bvTest)
	}

	// Put the biggest fractions first as an optimization
	sort.Slice(tm.targets, func(i, j int) bool {
		return tm.targets[j].Weight < tm.targets[i].Weight
	})

	return &tm, nil
}

func percentageValidate(tests []*BenchmarkTarget) error {
	total := 0
	for _, bvTest := range tests {
		total += bvTest.Weight
	}
	if total != 100 {
		return fmt.Errorf("test percentage total comes to %d, should be 100", total)
	}
	return nil
}
