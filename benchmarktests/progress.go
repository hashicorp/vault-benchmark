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
	ansiReset       = "\033[0m"
	ansiYellow      = "\033[33m"
	ansiCyan        = "\033[36m"
	ansiRed         = "\033[31m"
	ansiBold        = "\033[1m"
	ansiBrightBlack = "\033[90m" // gray — used for setup/cleanup stages (less prominent than attack)
	ansiEOL         = "\033[K"   // erase from cursor to end of line — eliminates stale trailing chars

	barWidth    = 20
	labelWidth  = 22
	flavorWidth = 32 // fixed-width flavor column; truncated to keep line length stable

	tickInterval     = 80 * time.Millisecond
	flavorUpdateRate = 19 // flavor text updates every 19 ticks (~1.5s); spinner animates every tick
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
	"negotiating with identity store",
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

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func compactCount(n int64) string {
	switch {
	case n >= 1_000_000:
		v := float64(n) / 1_000_000
		if v == float64(int64(v)) {
			return fmt.Sprintf("%dM", int64(v))
		}
		return fmt.Sprintf("%.1fM", v)
	case n >= 1_000:
		// Use integer tenths to avoid float rounding producing "1000.0k".
		tenths := n / 100 // e.g. 1500 → 15, 999999 → 9999
		whole := tenths / 10
		frac := tenths % 10
		if frac == 0 {
			return fmt.Sprintf("%dk", whole)
		}
		return fmt.Sprintf("%d.%dk", whole, frac)
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

// truncateLabel truncates s to at most labelWidth runes. The %-*s format verb
// pads but does not truncate, so long target names would overflow the line.
func truncateLabel(s string) string {
	runes := []rune(s)
	if len(runes) > labelWidth {
		return string(runes[:labelWidth-1]) + "…"
	}
	return s
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// stageProgress renders a live stderr line for a top-level stage.
// Call Complete, Fail, or Skip exactly once to stop the background goroutine.
// Calling more than one of these methods on the same instance is safe — only
// the first call takes effect; subsequent calls are no-ops.
type stageProgress struct {
	mu       sync.Mutex
	w        *os.File
	label    string
	started  time.Time
	phrases  []string
	names    []string
	reqs     atomic.Int64
	duration time.Duration // non-zero: attack stage uses time-based bar

	haltOnce       sync.Once
	stop           chan struct{}
	stopped        chan struct{}
	lastFlavorText string

	// tickCount is the monotone tick counter that drives phrase/name rotation.
	// phraseIdx tracks shuffle-aware phrase position independently because
	// shuffling the slice in-place means the position can't be derived from
	// tickCount alone.
	tickCount int
	phraseIdx int
}

func newStageProgress(w *os.File, label string, phrases []string, names []string, duration time.Duration) *stageProgress {
	// Copy phrases so in-place shuffles in nextFlavor don't mutate the
	// package-level phrase slices, which would be a data race if two
	// stageProgress instances ran concurrently.
	phrasesCopy := make([]string, len(phrases))
	copy(phrasesCopy, phrases)
	initialFlavor := ""
	if len(phrasesCopy) > 0 {
		initialFlavor = truncateFlavor(phrasesCopy[0])
	}
	p := &stageProgress{
		w:              w,
		label:          label,
		started:        time.Now(),
		phrases:        phrasesCopy,
		names:          names,
		duration:       duration,
		stop:           make(chan struct{}),
		stopped:        make(chan struct{}),
		lastFlavorText: initialFlavor,
	}
	go p.run()
	return p
}

func (p *stageProgress) run() {
	defer close(p.stopped)
	if !isTTY(p.w) {
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

func (p *stageProgress) redraw() {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.started)
	label := truncateLabel(p.label)

	if p.duration > 0 {
		// Flavor omitted — the numbers are the signal here.
		done := int(elapsed.Seconds())
		total := int(p.duration.Seconds())
		if done > total {
			done = total
		}
		est := fmtDuration(p.duration)
		bar := renderBar(done, total)
		reqs := p.reqs.Load()
		fmt.Fprintf(p.w, "\r  %s%-*s%s  %s  %s/~%s  %s reqs%s",
			ansiCyan, labelWidth, label, ansiReset,
			bar,
			fmtDuration(elapsed), est,
			compactCount(reqs),
			ansiEOL,
		)
	} else {
		flavor := p.nextFlavor()
		if p.tickCount%flavorUpdateRate == 0 {
			p.lastFlavorText = truncateFlavor(flavor)
		}
		spinner := ansiBrightBlack + spinnerFrames[p.tickCount%len(spinnerFrames)] + ansiReset
		fmt.Fprintf(p.w, "\r  %s%-*s%s  %s  %s  %s%s",
			ansiBrightBlack, labelWidth, label, ansiReset,
			spinner,
			fmtDuration(elapsed),
			p.lastFlavorText,
			ansiEOL,
		)
	}
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%02dh", days, h)
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

func (p *stageProgress) halt() {
	p.haltOnce.Do(func() {
		close(p.stop)
		<-p.stopped
	})
}

// The trailing blank line visually separates this stage from whatever follows.
func (p *stageProgress) Complete() {
	p.halt()

	elapsed := time.Since(p.started)
	reqs := p.reqs.Load()
	label := truncateLabel(p.label)

	if isTTY(p.w) {
		if p.duration > 0 {
			suffix := ""
			if reqs > 0 {
				suffix = "  " + compactCount(reqs) + " reqs"
			}
			fmt.Fprintf(p.w, "\r  %s%-*s%s  %s  %s%s%s\n\n",
				ansiBold, labelWidth, label, ansiReset,
				renderBar(1, 1),
				fmtDuration(elapsed), suffix,
				ansiEOL,
			)
		} else {
			fmt.Fprintf(p.w, "\r  %s%-*s%s  ✔  %s%s\n\n",
				ansiBold, labelWidth, label, ansiReset,
				fmtDuration(elapsed),
				ansiEOL,
			)
		}
		return
	}
	if reqs > 0 {
		fmt.Fprintf(p.w, "  %-*s  %s  %s reqs\n", labelWidth, label, fmtDuration(elapsed), compactCount(reqs))
	} else {
		fmt.Fprintf(p.w, "  %-*s  %s\n", labelWidth, label, fmtDuration(elapsed))
	}
}

// Skip halts without printing. Use when a stage finished too quickly to be worth reporting.
func (p *stageProgress) Skip() {
	p.halt()
}

func (p *stageProgress) Fail(err error) {
	p.halt()

	elapsed := time.Since(p.started)
	label := truncateLabel(p.label)
	if isTTY(p.w) {
		fmt.Fprintf(p.w, "\r  %s%-*s%s  failed  %s  %v%s\n",
			ansiRed+ansiBold, labelWidth, label, ansiReset,
			fmtDuration(elapsed), err,
			ansiEOL,
		)
		return
	}
	fmt.Fprintf(p.w, "  %-*s  failed  %s  %v\n", labelWidth, label, fmtDuration(elapsed), err)
}

func targetNames[T *BenchmarkTarget | BenchmarkTarget](targets []T) []string {
	names := make([]string, len(targets))
	for i, t := range targets {
		switch v := any(t).(type) {
		case *BenchmarkTarget:
			names[i] = v.Name
		case BenchmarkTarget:
			names[i] = v.Name
		}
	}
	return names
}
