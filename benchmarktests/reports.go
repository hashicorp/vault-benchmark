// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

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
	// TODO: "total" is a reserved key; a target named "total" silently corrupts the aggregate. Reject in config validation.
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
	// TODO: unmatched results (no target hit) are counted in "total" but dropped from per-target buckets, distorting comparisons. Log at Warn or add an "unmatched" bucket.
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
func (r *Reporter) ReportTerse(w io.Writer) error {
	terminal := false
	if f, ok := w.(*os.File); ok {
		terminal = isTTY(f)
	}

	paint := func(ansi, s string) string {
		if !terminal || ansi == "" {
			return s
		}
		return ansi + s + ansiReset
	}

	successColor := func(ratio float64) string {
		switch {
		case ratio < 0.80:
			return ansiRed
		case ratio < 0.95:
			return ansiYellow
		default:
			return ""
		}
	}

	metricNames := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		if name == "total" {
			continue
		}
		metricNames = append(metricNames, name)
	}
	natSort(metricNames)

	const maxOpWidth = 24

	opWidth := len("TOTAL")
	for _, name := range metricNames {
		if n := len([]rune(name)); n > opWidth {
			opWidth = n
		}
	}
	if opWidth > maxOpWidth {
		opWidth = maxOpWidth
	}

	// truncOp truncates a name to opWidth runes, adding "…" if cut.
	// Names exceeding maxOpWidth come from user config; truncation is cosmetic
	// and prevents terminal line overflow without rejecting valid configs.
	truncOp := func(s string) string {
		runes := []rune(s)
		if len(runes) > opWidth {
			return string(runes[:opWidth-1]) + "…"
		}
		return s
	}

	// Fixed numeric column widths. Format value to width first, then color —
	// ANSI codes don't count toward padding this way.
	const (
		wCount = 7  // max "9999.9k"
		wRate  = 8  // max "99999.99"
		wThru  = 8
		wLat   = 10 // max "99999.99ms"
		wOk    = 9  // "100.00%%"  → "success%"
	)

	// rc formats a plain value right-aligned to width, then applies dim gray.
	rc := func(width int, s string) string {
		return paint(ansiBrightBlack, fmt.Sprintf("%*s", width, s))
	}

	fmt.Fprintf(w, "\n%s\n", paint(ansiBrightBlack, r.clientAddr))

	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s  %s\n",
		paint(ansiBold, fmt.Sprintf("%-*s", opWidth, "op")),
		paint(ansiBold, fmt.Sprintf("%*s", wCount, "count")),
		paint(ansiBold, fmt.Sprintf("%*s", wRate, "rate/s")),
		paint(ansiBold, fmt.Sprintf("%*s", wThru, "thru/s")),
		paint(ansiBold, fmt.Sprintf("%*s", wLat, "mean")),
		paint(ansiBold, fmt.Sprintf("%*s", wLat, "p95")),
		paint(ansiBold, fmt.Sprintf("%*s", wLat, "p99")),
		paint(ansiBold, fmt.Sprintf("%*s", wOk, "success%")),
	)

	printRow := func(label, key string) {
		m := r.metrics[key]
		sc := successColor(m.Success)
		var opAnsi string
		switch {
		case label == "TOTAL" && sc != "":
			opAnsi = ansiBold + sc
		case label == "TOTAL":
			opAnsi = ansiBold
		default:
			opAnsi = sc
		}
		opField := paint(opAnsi, fmt.Sprintf("%-*s", opWidth, truncOp(label)))

		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s  %s\n",
			opField,
			rc(wCount, compactCount(int64(m.Requests))),
			rc(wRate, compactRate(m.Rate)),
			rc(wThru, compactRate(m.Throughput)),
			rc(wLat, fmtLatency(m.Latencies.Mean)),
			rc(wLat, fmtLatency(m.Latencies.P95)),
			rc(wLat, fmtLatency(m.Latencies.P99)),
			rc(wOk, fmt.Sprintf("%.2f%%", m.Success*100)),
		)
	}

	for _, name := range metricNames {
		printRow(name, name)
	}
	// The aggregate across all tests is shown last, separated by a rule so it doesn't read as just another op named "total".
	if _, ok := r.metrics["total"]; ok {
		d := func(n int) string { return paint(ansiBrightBlack, strings.Repeat("-", n)) }
		fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s  %s\n",
			d(opWidth), d(wCount), d(wRate), d(wThru),
			d(wLat), d(wLat), d(wLat), d(wOk),
		)
		printRow("TOTAL", "total")
	}
	return nil
}

func (r *Reporter) ReportVerbose(w io.Writer) error {
	terminal := false
	if f, ok := w.(*os.File); ok {
		terminal = isTTY(f)
	}

	sections := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		if name == "total" {
			continue
		}
		sections = append(sections, name)
	}
	natSort(sections)

	printSection := func(title, key string) error {
		m := r.metrics[key]

		color := ""
		switch {
		case m.Success < 0.80:
			color = ansiRed
		case m.Success < 0.95:
			color = ansiYellow
		}

		header := title
		if terminal {
			if title == "TOTAL" {
				header = ansiBold + color + title + ansiReset
			} else if color != "" {
				header = color + title + ansiReset
			}
		}

		successStr := fmt.Sprintf("%.2f%%", m.Success*100)
		if terminal && color != "" {
			successStr = color + successStr + ansiReset
		}

		codes := make([]string, 0, len(m.StatusCodes))
		for code := range m.StatusCodes {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		codeStrs := make([]string, 0, len(codes))
		for _, code := range codes {
			codeStrs = append(codeStrs, fmt.Sprintf("%s:%d", code, m.StatusCodes[code]))
		}

		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		fmt.Fprintln(w)
		fmt.Fprintln(w, header)
		fmt.Fprintf(tw, "Requests\t%d  (%.2f/s)\n", m.Requests, m.Rate)
		fmt.Fprintf(tw, "Latencies\tmin %s  p50 %s  p90 %s  p95 %s  p99 %s  max %s  mean %s\n",
			fmtLatency(m.Latencies.Min),
			fmtLatency(m.Latencies.P50),
			fmtLatency(m.Latencies.P90),
			fmtLatency(m.Latencies.P95),
			fmtLatency(m.Latencies.P99),
			fmtLatency(m.Latencies.Max),
			fmtLatency(m.Latencies.Mean),
		)
		fmt.Fprintf(tw, "Success\t%s\n", successStr)
		fmt.Fprintf(tw, "Status codes\t%s\n", strings.Join(codeStrs, "  "))
		if len(m.Errors) > 0 {
			fmt.Fprintf(tw, "Errors\t%s\n", strings.Join(m.Errors, "  "))
		}
		return tw.Flush()
	}

	for _, name := range sections {
		if err := printSection(name, name); err != nil {
			return err
		}
	}
	// The aggregate across all tests is shown last, labeled so it doesn't read
	// as just another test named "total".
	if _, ok := r.metrics["total"]; ok {
		return printSection("TOTAL", "total")
	}
	return nil
}

// Above 1s delegates to fmtDuration (e.g. "1m02s") so extreme latencies remain readable.
func fmtLatency(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fµs", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	default:
		return fmtDuration(d)
	}
}

// Produces at most 8 chars, matching the wRate/wThru column widths.
func compactRate(v float64) string {
	switch {
	case v >= 1_000_000:
		return fmt.Sprintf("%.1fM", v/1_000_000)
	case v >= 1_000:
		return fmt.Sprintf("%.1fk", v/1_000)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}
