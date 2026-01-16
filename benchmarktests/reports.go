// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	vegeta "github.com/tsenart/vegeta/v12/lib"
)

var attackResult = prometheus.NewSummaryVec(prometheus.SummaryOpts{
	Name:       "bench_attack_time_seconds",
	Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
}, []string{"attack"})

var attackErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "bench_attack_errors",
}, []string{"attack", "error"})

func init() {
	prometheus.MustRegister(attackResult)
	prometheus.MustRegister(attackErrors)
}

type Reporter struct {
	tm         *TargetMulti
	clientAddr string
	metrics    map[string]*vegeta.Metrics
}

type JSONReport struct {
	TargetAddr string                     `json:"target_addr"`
	Metrics    map[string]*vegeta.Metrics `json:"metrics"`
}

func FromReader(r io.Reader) ([]*Reporter, error) {
	d := json.NewDecoder(r)
	var reporters []*Reporter
	for d.More() {
		var unmarshaled JSONReport
		if err := d.Decode(&unmarshaled); err != nil {
			return nil, fmt.Errorf("could not decode report JSON (index %d): %w", len(reporters), err)
		}
		rpt := newReporter(&TargetMulti{}, nil)
		rpt.clientAddr = unmarshaled.TargetAddr
		rpt.metrics = unmarshaled.Metrics
		reporters = append(reporters, rpt)
	}
	return reporters, nil
}

func newReporter(tm *TargetMulti, client *api.Client) *Reporter {
	clientAddress := "N/A"
	if client != nil {
		clientAddress = client.Address()
	}
	r := &Reporter{tm: tm, clientAddr: clientAddress}
	r.metrics = make(map[string]*vegeta.Metrics, len(tm.targets)+1)
	r.metrics["total"] = &vegeta.Metrics{}
	for _, t := range tm.targets {
		r.metrics[t.Name] = &vegeta.Metrics{}
	}
	return r
}

func (r *Reporter) Add(result *vegeta.Result) {
	r.metrics["total"].Add(result)
	for _, target := range r.tm.targets {
		if result.Method == target.Method && strings.HasPrefix(result.URL, r.clientAddr+target.PathPrefix) {
			r.metrics[target.Name].Add(result)
			attackResult.WithLabelValues(target.Name).Observe(result.Latency.Seconds())
			if result.Error != "" {
				attackErrors.WithLabelValues(target.Name, result.Error).Inc()
			}
			break
		}
	}
	// TODO what if we didn't find any match?
}

func (r *Reporter) Close() {
	for name := range r.metrics {
		r.metrics[name].Close()
	}
}

func (r *Reporter) ReportJSON(w io.Writer) error {
	j := json.NewEncoder(w)
	return j.Encode(&JSONReport{
		TargetAddr: r.clientAddr,
		Metrics:    r.metrics,
	})
}

func (r *Reporter) ReportVerbose(w io.Writer) error {
	sections := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		sections = append(sections, name)
	}
	sort.Slice(sections, func(i, j int) bool {
		if sections[i] == "total" {
			return true
		}
		return sections[i] < sections[j]
	})
	for _, name := range sections {
		fmt.Fprintln(w)
		fmt.Fprintln(w, name)
		if err := vegeta.NewTextReporter(r.metrics[name]).Report(w); err != nil {
			return fmt.Errorf("report error: %v", err)
		}
	}
	return nil
}

func (r *Reporter) ReportTerse(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', tabwriter.StripEscape)
	fmt.Fprintf(tw, "Target: %v\n", r.clientAddr)
	fmt.Fprintf(tw, "op\tcount\trate\tthroughput\tmean\t95th%%\t99th%%\tsuccessRatio\n")
	const fmtstr = "%s\t%d\t%f\t%f\t%s\t%s\t%s\t%.2f%%\n"

	metricNames := make([]string, 0)
	for name := range r.metrics {
		metricNames = append(metricNames, name)
	}

	sort.Slice(metricNames, func(i, j int) bool {
		return metricNames[i] < metricNames[j]
	})

	for _, name := range metricNames {
		m := r.metrics[name]
		if name != "total" {
			fmt.Fprintf(tw, fmtstr, name, m.Requests, m.Rate, m.Throughput, m.Latencies.Mean, m.Latencies.P95, m.Latencies.P99, m.Success*100)
		}
	}
	tw.Flush()
	return nil
}
