// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
)

// progressDivisions controls how many progress log lines runPhaseN emits per phase.
const progressDivisions = 5

// No retries or backoff: failures are collected and returned as-is.
// A Vault write failure during setup indicates a configuration problem, not a transient condition.
// TODO: per-workload retry/backoff when transient 429s during setup become a
// reported issue; generic backoff here would mask real failures.
func runConcurrentN(n, start, end int, fn func(idx int) error) error {
	if end < start {
		return nil
	}

	total := end - start + 1
	jobs := make(chan int, n)
	// Sized to total jobs so workers never block on send, even under total failure.
	errs := make(chan error, total)

	var allErrs []error
	collected := make(chan struct{})
	go func() {
		for err := range errs {
			allErrs = append(allErrs, err)
		}
		close(collected)
	}()

	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if err := fn(idx); err != nil {
					errs <- err
				}
			}
		}()
	}

	for idx := start; idx <= end; idx++ {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(errs)
	<-collected

	return errors.Join(allErrs...)
}

func runPhaseN(logger hclog.Logger, phase string, n, total int, fn func(idx int) error, startFields ...any) error {
	if total <= 0 {
		return nil
	}

	start := time.Now()
	logger.Info(phase+" start", append([]any{"total", total}, startFields...)...)

	progressInterval := ceilDiv(total, progressDivisions)
	var done atomic.Int64

	err := runConcurrentN(n, 0, total-1, func(idx int) error {
		if err := fn(idx); err != nil {
			return err
		}
		d := done.Add(1)
		if d%int64(progressInterval) == 0 || int(d) == total {
			logger.Info(phase, "progress", fmt.Sprintf("%d/%d", d, total))
		}
		return nil
	})
	if err != nil {
		return err
	}

	logger.Info(phase+" complete", "total", total, "elapsed", time.Since(start).String())
	return nil
}

func deleteConcurrentN(logger hclog.Logger, phase string, client *api.Client, pathPrefix string, count, n int, keyFn func(idx int) string) error {
	return runPhaseN(logger, phase, n, count, func(idx int) error {
		key := keyFn(idx)
		if _, err := client.Logical().Delete(pathPrefix + key); err != nil {
			return fmt.Errorf("error deleting %s%s: %w", pathPrefix, key, err)
		}
		return nil
	})
}
