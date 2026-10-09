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

const (
	progressDivisions = 5

	// identityConcurrency and kvSeedConcurrency are independent tuning axes: identity
	// setup hits the identity store (always serialized by Vault regardless of storage
	// backend), while KV setup hits the secrets engine (may benefit from n>1 on
	// integrated-storage clusters). Both default to 1 (serial). To experiment locally,
	// raise the relevant constant; do not raise on production clusters without profiling.
	identityConcurrency = 1
	kvSeedConcurrency   = 1
)

// Not retried: a write failure during setup indicates a config problem, not a transient condition.
func runConcurrent(n, count int, fn func(idx int) error) error {
	if n <= 0 {
		return fmt.Errorf("runConcurrent: n must be > 0, got %d", n)
	}
	if count <= 0 {
		return nil
	}

	jobs := make(chan int, n)
	errs := make(chan error, count)

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

	for idx := range count {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(errs)
	<-collected

	return errors.Join(allErrs...)
}

func runPhase(logger hclog.Logger, phase string, n, total int, fn func(idx int) error, startFields ...any) error {
	if total <= 0 {
		return nil
	}

	start := time.Now()
	logger.Info(phase+" start", append([]any{"total", total}, startFields...)...)

	progressInterval := ceilDiv(total, progressDivisions)
	var done atomic.Int64

	err := runConcurrent(n, total, func(idx int) error {
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

func deletePhase(logger hclog.Logger, phase string, client *api.Client, pathPrefix string, n, count int, keyFn func(idx int) string) error {
	return runPhase(logger, phase, n, count, func(idx int) error {
		key := keyFn(idx)
		if _, err := client.Logical().Delete(pathPrefix + key); err != nil {
			return fmt.Errorf("error deleting %s%s: %w", pathPrefix, key, err)
		}
		return nil
	})
}
