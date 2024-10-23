// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"time"

	"github.com/hashicorp/vault/api"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

func Attack(tm *TargetMulti, client *api.Client, duration time.Duration, rps int, workers int, dnsCaching time.Duration) (*Reporter, error) {
	rate := vegeta.Rate{Freq: rps, Per: time.Second}
	opts := []func(*vegeta.Attacker){
		vegeta.Workers(uint64(workers)),
		vegeta.MaxWorkers(uint64(workers)),
		vegeta.DNSCaching(dnsCaching),
	}
	if client != nil {
		opts = append(opts, vegeta.Client(client.CloneConfig().HttpClient))
	}
	attacker := vegeta.NewAttacker(opts...)

	targeter, err := tm.Targeter(client)
	if err != nil {
		return nil, err
	}
	rpt := newReporter(tm, client)
	for res := range attacker.Attack(targeter, rate, duration, "Big Bang!") {
		rpt.Add(res)
	}
	rpt.Close()

	return rpt, nil
}
