// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiRed    = "\033[31m"
	ansiBold   = "\033[1m"
	ansiEOL    = "\033[K" // erase from cursor to end of line — eliminates stale trailing chars

	barWidth    = 20
	labelWidth  = 22
	flavorWidth = 32 // fixed-width flavor column; truncated to keep line length stable

	tickInterval = 250 * time.Millisecond
)

var setupPhrases = []string{
	"provisioning mounts",
	"writing roles",
	"seeding secrets",
	"configuring policies",
	"populating entities",
	"building groups",
	"wiring aliases",
	"validating logins",
	"enabling auth methods",
	"writing credentials",
	"teaching Vault new tricks",
	"bribing the storage backend",
	"asking Vault nicely",
	"negotiating with the identity store",
	"counting to a million (slowly)",
}

var attackPhrases = []string{
	"hammering Vault",
	"sending requests",
	"measuring latency",
	"stress testing",
	"load testing",
	"running benchmarks",
	"firing requests",
	"collecting metrics",
	"pushing the limits",
	"going full send",
}

var cleanupPhrases = []string{
	"removing mounts",
	"deleting entities",
	"cleaning up groups",
	"unmounting auth methods",
	"tidying up policies",
	"sweeping the identity store",
	"leaving no trace",
	"pretending this never happened",
}

// isTTY uses only stdlib — no external dependency — so the progress display
// never pulls in a terminal-detection library.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// compactCount: 999 → "999", 1500 → "1.5k", 2000000 → "2M".
func compactCount(n int64) string {
	switch {
	case n >= 1_000_000:
		v := float64(n) / 1_000_000
		if v == float64(int64(v)) {
			return fmt.Sprintf("%dM", int64(v))
		}
		return fmt.Sprintf("%.1fM", v)
	case n >= 1_000:
		v := float64(n) / 1_000
		if v == float64(int64(v)) {
			return fmt.Sprintf("%dk", int64(v))
		}
		return fmt.Sprintf("%.1fk", v)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func renderBar(done, total int) string {
	if total <= 0 {
		return "[" + strings.Repeat("░", barWidth) + "]"
	}
	filled := done * barWidth / total
	if filled > barWidth {
		filled = barWidth
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled) + "]"
}

// truncateFlavor pads or truncates s to exactly flavorWidth runes so the
// line length never grows or shrinks between ticks.
func truncateFlavor(s string) string {
	runes := []rune(s)
	if len(runes) >= flavorWidth {
		return string(runes[:flavorWidth])
	}
	return s + strings.Repeat(" ", flavorWidth-len(runes))
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// stageProgress renders a live stderr line for a top-level stage.
// Call Complete, Fail, or Skip exactly once to stop the background goroutine.
type stageProgress struct {
	mu       sync.Mutex
	w        *os.File
	tty      bool
	label    string
	started  time.Time
	phrases  []string
	names    []string
	reqs     atomic.Int64
	duration time.Duration // non-zero: attack stage uses time-based bar

	// targetsDone drives ETA for the setup stage.
	targetsDone atomic.Int64
	stop        chan struct{}
	stopped     chan struct{}

	// tickCount is the monotone tick counter that drives phrase/name rotation.
	// phraseIdx tracks shuffle-aware phrase position independently because
	// shuffling the slice in-place means the position can't be derived from
	// tickCount alone.
	tickCount int
	phraseIdx int
}

func newStageProgress(w *os.File, label string, phrases []string, names []string, duration time.Duration) *stageProgress {
	p := &stageProgress{
		w:        w,
		tty:      isTTY(w),
		label:    label,
		started:  time.Now(),
		phrases:  phrases,
		names:    names,
		duration: duration,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *stageProgress) run() {
	defer close(p.stopped)
	if !p.tty {
		<-p.stop
		return
	}
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.redraw()
		}
	}
}

// redraw writes a rewriting line. ansiEOL at end of every write erases stale trailing chars.
func (p *stageProgress) redraw() {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.started)

	if p.duration > 0 {
		// Flavor column omitted: request numbers are the signal during attack.
		done := int(elapsed.Seconds())
		total := int(p.duration.Seconds())
		if done > total {
			done = total
		}
		remaining := p.duration - elapsed
		if remaining < 0 {
			remaining = 0
		}
		bar := renderBar(done, total)
		reqs := p.reqs.Load()
		fmt.Fprintf(p.w, "\r  %s%-*s%s  %s%s%s  %s elapsed  ~%s left  %s reqs%s",
			ansiCyan, labelWidth, p.label, ansiReset,
			ansiYellow, bar, ansiReset,
			fmtDuration(elapsed),
			fmtDuration(remaining.Round(time.Second)),
			compactCount(reqs),
			ansiEOL,
		)
	} else {
		flavor := truncateFlavor(p.nextFlavor())
		spinner := ansiYellow + spinnerFrames[int(elapsed/tickInterval)%len(spinnerFrames)] + ansiReset
		eta := p.eta(elapsed)
		fmt.Fprintf(p.w, "\r  %s%-*s%s  %s  %s elapsed  %s  %s%s",
			ansiCyan, labelWidth, p.label, ansiReset,
			spinner,
			fmtDuration(elapsed),
			eta,
			flavor,
			ansiEOL,
		)
	}
}

// eta: not concurrency-safe — caller must hold mu.
func (p *stageProgress) eta(elapsed time.Duration) string {
	done := p.targetsDone.Load()
	total := int64(len(p.names))
	if done <= 0 || total <= 0 || done >= total {
		return "~? left     "
	}
	remaining := time.Duration(float64(elapsed) / float64(done) * float64(total-done))
	return "~" + fmtDuration(remaining.Round(time.Second)) + " left"
}

// fmtDuration: "3s", "1m02s", "1h04m".
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// nextFlavor: not concurrency-safe — caller must hold mu.
func (p *stageProgress) nextFlavor() string {
	p.tickCount++
	if len(p.names) > 0 && p.tickCount%3 == 1 {
		nameIdx := (p.tickCount / 3) % len(p.names)
		return p.names[nameIdx]
	}
	if len(p.phrases) > 0 {
		phrase := p.phrases[p.phraseIdx%len(p.phrases)]
		p.phraseIdx++
		if p.phraseIdx%len(p.phrases) == 0 {
			rand.Shuffle(len(p.phrases), func(i, j int) {
				p.phrases[i], p.phrases[j] = p.phrases[j], p.phrases[i]
			})
		}
		return phrase
	}
	return ""
}

func (p *stageProgress) AddReqs(n int64) {
	p.reqs.Add(n)
}

// TargetComplete improves the ETA estimate; call once per completed setup target.
func (p *stageProgress) TargetComplete() {
	p.targetsDone.Add(1)
}

func (p *stageProgress) halt() {
	close(p.stop)
	<-p.stopped
}

// Complete commits the final success line and a trailing blank line to visually
// separate this stage from whatever follows.
func (p *stageProgress) Complete() {
	p.halt()

	elapsed := time.Since(p.started)
	reqs := p.reqs.Load()

	if p.tty {
		suffix := ""
		if reqs > 0 {
			suffix = "  " + compactCount(reqs) + " reqs"
		}
		fmt.Fprintf(p.w, "\r  %s%-*s%s  %s%s%s  %s%s%s\n\n",
			ansiBold+ansiGreen, labelWidth, p.label, ansiReset,
			ansiGreen, renderBar(1, 1), ansiReset,
			fmtDuration(elapsed), suffix,
			ansiEOL,
		)
		return
	}
	if reqs > 0 {
		fmt.Fprintf(p.w, "  %-*s  complete  %s  %s reqs\n\n", labelWidth, p.label, fmtDuration(elapsed), compactCount(reqs))
	} else {
		fmt.Fprintf(p.w, "  %-*s  complete  %s\n\n", labelWidth, p.label, fmtDuration(elapsed))
	}
}

// Skip halts without printing. Use when a stage finished too quickly to be worth reporting.
func (p *stageProgress) Skip() {
	p.halt()
}

func (p *stageProgress) Fail(err error) {
	p.halt()

	elapsed := time.Since(p.started)
	if p.tty {
		fmt.Fprintf(p.w, "\r  %s%-*s%s  failed  %s  %v%s\n",
			ansiRed+ansiBold, labelWidth, p.label, ansiReset,
			fmtDuration(elapsed), err,
			ansiEOL,
		)
		return
	}
	fmt.Fprintf(p.w, "  %-*s  failed  %s  %v\n", labelWidth, p.label, fmtDuration(elapsed), err)
}

func targetNames(targets []*BenchmarkTarget) []string {
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.Name
	}
	return names
}
