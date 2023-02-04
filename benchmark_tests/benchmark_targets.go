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

var TestList = make(map[string]func() BenchmarkTarget)

type targetFraction struct {
	name       string
	method     string
	pathPrefix string
	percent    int // e.g. 30 is 30%
	target     func(*api.Client) vegeta.Target
	cleanup    func(*api.Client) error
}

type BenchmarkTest struct {
	Builder BenchmarkTarget
	Name    string `hcl:"name,label"`
	Type    string `hcl:"type,label"`
	Weight  int    `hcl:"weight,optional"`
	Config  interface{}
	Target  *vegeta.Target
	Remain  hcl.Body `hcl:",remain"`
}

// TargetMulti allows building a vegeta targetter that chooses between various
// operations randomly following a specified distribution.
type TargetMulti struct {
	fractions []targetFraction
}

func (tm TargetMulti) validate() error {
	total := 0
	for _, fraction := range tm.fractions {
		total += fraction.percent
	}
	if total != 100 {
		return fmt.Errorf("test percentage total comes to %d, should be 100", total)
	}
	return nil
}

func (tm TargetMulti) choose(i int) targetFraction {
	if i > 99 || i < 0 {
		panic("i must be between 0 and 99")
	}

	total := 0
	for _, fraction := range tm.fractions {
		total += fraction.percent
		if i < total {
			return fraction
		}
	}

	panic("unreachable")
}

func (tm TargetMulti) Cleanup(client *api.Client) error {
	for _, fraction := range tm.fractions {
		if err := fraction.cleanup(client); err != nil {
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
		f := tm.choose(rnd)
		*tgt = f.target(client)
		return nil
	}, nil
}

func (tm TargetMulti) DebugInfo(client *api.Client) {
	for index, fraction := range tm.fractions {
		fmt.Printf("Target %d: %v\n", index, fraction.name)
		fmt.Printf("\tMethod: %v\n", fraction.method)
		fmt.Printf("\tPath Prefix: %v\n", string(fraction.pathPrefix))
		target := fraction.target(client)
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

func BuildTargets(tests []*BenchmarkTest, client *api.Client, caPEM string, clientCAPem string) (*TargetMulti, error) {
	var tm TargetMulti

	for _, bvTest := range tests {
		currTest, err := bvTest.Builder.Setup(client, true, bvTest.Config)
		if err != nil {
			return nil, err
		}
		currTargetFraction := currTest.createTargetFraction()
		currTargetFraction.name = bvTest.Name
		currTargetFraction.percent = bvTest.Weight
		currTargetFraction.target = currTest.Target
		currTargetFraction.cleanup = currTest.Cleanup

		tm.fractions = append(tm.fractions, currTargetFraction)
	}

	// Put the biggest fractions first as an optimization
	sort.Slice(tm.fractions, func(i, j int) bool {
		return tm.fractions[j].percent < tm.fractions[i].percent
	})

	err := tm.validate()
	if err != nil {
		return nil, err
	}
	return &tm, nil
}
