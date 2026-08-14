// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

type TopLevelTargetConfig struct {
	Duration     time.Duration
	RandomMounts bool
}

const (
	VaultBenchmarkEnvVarPrefix = "VAULT_BENCHMARK_"
)

type BenchmarkBuilder interface {
	Target(client *api.Client) vegeta.Target
	Setup(client *api.Client, mountName string, config *TopLevelTargetConfig) (BenchmarkBuilder, error)
	Cleanup(client *api.Client) error
	ParseConfig(body hcl.Body) error
	GetTargetInfo() TargetInfo
	Flags(fs *flag.FlagSet)
}

var (
	// TODO: targets with multiple actions (transit, gcpkms, totp) register one TestList entry per action,
	// mirroring the identity workload pattern incorrectly. The correct fix is a single registration per engine
	// with an action field in the HCL config block validated in ParseConfig — identical to how identity uses
	// workload. This is a breaking change to user-facing HCL type keys (e.g. "transit_sign" → "transit") and
	// requires a docs update and migration note. Defer to a dedicated PR.
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

// TODO: collapse GetTargetInfo into ConfigureTarget, removing TargetInfo and the interface method for all 50+ targets
func (bt *BenchmarkTarget) ConfigureTarget(client *api.Client) {
	bt.Target = bt.Builder.Target
	tInfo := bt.Builder.GetTargetInfo()
	bt.PathPrefix = tInfo.pathPrefix
	bt.Method = tInfo.method
}

// TargetMulti chooses between various operations randomly following a specified distribution.
type TargetMulti struct {
	targets []BenchmarkTarget
}

func (tm TargetMulti) choose(i int) *BenchmarkTarget {
	if i > 99 || i < 0 {
		panic(fmt.Sprintf("choose: i must be between 0 and 99, got %d", i))
	}

	total := 0
	for _, target := range tm.targets {
		total += target.Weight
		if i < total {
			return &target
		}
	}

	panic(fmt.Sprintf("choose: weights do not sum to 100 (got %d), unreachable with i=%d", total, i))
}

func (tm TargetMulti) Cleanup(client *api.Client) error {
	type CleanupMsg struct {
		err        error
		targetName string
	}

	wg := new(sync.WaitGroup)
	errch := make(chan CleanupMsg)
	var errs []error

	for _, target := range tm.targets {
		target := target
		wg.Add(1)
		targetLogger.Debug("cleaning up", "target", target.Name)
		go func() {
			defer wg.Done()
			errch <- CleanupMsg{
				err:        target.Builder.Cleanup(client),
				targetName: target.Name,
			}
		}()
	}

	for range tm.targets {
		cleanupMsg := <-errch
		if cleanupMsg.err != nil {
			errs = append(errs, cleanupMsg.err)
			targetLogger.Error("error cleaning up", "target", cleanupMsg.targetName, "error", cleanupMsg.err.Error())
		} else {
			targetLogger.Trace("done cleaning up", "target", cleanupMsg.targetName)
		}
	}
	return errors.Join(errs...)
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
	debugInfoHeader := "\n=== Debug Info ===\n"
	debugInfoHeader += fmt.Sprintf("Client: %s\n", client.Address())
	debugInfoFooter := "==================\n"
	for index, benchTarget := range tm.targets {
		targetDebugInfo := debugInfoHeader + fmt.Sprintf("Target %d: %v\n", index, benchTarget.Name) +
			fmt.Sprintf("Method: %v\n", benchTarget.Method) +
			fmt.Sprintf("Path Prefix: %v\n", benchTarget.PathPrefix)

		target := benchTarget.Target(client)
		req, err := target.Request()
		if err != nil {
			targetLogger.Error(fmt.Sprintf("Got err building target: %v", err))
			os.Exit(1)
		}
		targetLogger.Debug(targetDebugInfo + fmt.Sprintf("Request: %v\n", req.URL.String()) + debugInfoFooter)

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
		targetLogger.Debug(targetDebugInfo + fmt.Sprintf("Response: %v\n", resp.Status) +
			fmt.Sprintf("Response Body: %v", string(rawBody)) + debugInfoFooter)
		if resp.StatusCode >= 400 {
			targetLogger.Debug("Got error response from server on testing request; exiting")
			os.Exit(1)
		}
	}
}

func BuildTargets(client *api.Client, tests []*BenchmarkTarget, logger *hclog.Logger, config *TopLevelTargetConfig) (*TargetMulti, error) {
	var tm TargetMulti
	var err error
	targetLogger = *logger

	err = percentageValidate(tests)
	if err != nil {
		return nil, err
	}

	for _, bvTest := range tests {
		targetLogger.Debug("setting up target", "target", hclog.Fmt("%v", bvTest.Name))
		mountName := bvTest.Name
		if bvTest.MountName != "" {
			mountName = bvTest.MountName
		}
		bvTest.Builder, err = bvTest.Builder.Setup(client, mountName, config)
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
