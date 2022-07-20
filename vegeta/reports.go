package vegeta

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

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

type reporter struct {
	tm         *TargetMulti
	clientAddr string
	metrics    map[string]*vegeta.Metrics
}

func FromReader(r io.Reader) (*reporter, error) {
	d := json.NewDecoder(r)
	m := make(map[string]*vegeta.Metrics)
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	rpt := newReporter(&TargetMulti{}, nil)
	rpt.metrics = m
	return rpt, nil
}

func newReporter(tm *TargetMulti, client *api.Client) *reporter {
	r := &reporter{tm: tm, clientAddr: client.Address()}
	r.metrics = make(map[string]*vegeta.Metrics, len(tm.fractions)+1)
	r.metrics["total"] = &vegeta.Metrics{}
	for _, f := range tm.fractions {
		r.metrics[f.name] = &vegeta.Metrics{}
	}
	return r
}

func (r *reporter) Add(result *vegeta.Result) {
	r.metrics["total"].Add(result)
	for _, fraction := range r.tm.fractions {
		if result.Method == fraction.method && strings.HasPrefix(result.URL, r.clientAddr+fraction.pathPrefix) {
			r.metrics[fraction.name].Add(result)
			attackResult.WithLabelValues(fraction.name).Observe(result.Latency.Seconds())
			if result.Error != "" {
				attackErrors.WithLabelValues(fraction.name, result.Error).Inc()
			}
			break
		}
	}
	// TODO what if we didn't find any match?
}

func (r *reporter) Close() {
	for name := range r.metrics {
		r.metrics[name].Close()
	}
}

func (r *reporter) ReportJSON(w io.Writer) error {
	j := json.NewEncoder(w)
	return j.Encode(r.metrics)
}

func (r *reporter) ReportVerbose(w io.Writer) error {
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

func (r *reporter) ReportTerse(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', tabwriter.StripEscape)
	fmt.Fprintf(tw, "op\tcount\trate\tthroughput\tmean\t95th%%\t99th%%\tsuccessRatio\n")
	const fmtstr = "%s\t%d\t%f\t%f\t%s\t%s\t%s\t%.2f%%\n"
	for name, m := range r.metrics {
		if name != "total" {
			fmt.Fprintf(tw, fmtstr, name, m.Requests, m.Rate, m.Throughput, m.Latencies.Mean, m.Latencies.P95, m.Latencies.P99, m.Success*100)
		}
	}
	tw.Flush()
	return nil
}
