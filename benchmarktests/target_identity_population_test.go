// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import "testing"

func TestSampleIndices(t *testing.T) {
	t.Run("returns k distinct in-range indices", func(t *testing.T) {
		const n, k = 1000, 50
		idxs := sampleIndices(n, k)
		if len(idxs) != k {
			t.Fatalf("got %d indices, want %d", len(idxs), k)
		}

		seen := make(map[int]struct{}, len(idxs))
		for _, idx := range idxs {
			if idx < 1 || idx > n {
				t.Fatalf("index %d out of range [1, %d]", idx, n)
			}
			if _, dup := seen[idx]; dup {
				t.Fatalf("duplicate index %d", idx)
			}
			seen[idx] = struct{}{}
		}
	})

	t.Run("returns all indices when k >= n", func(t *testing.T) {
		const n = 5
		for _, k := range []int{n, n + 3} {
			idxs := sampleIndices(n, k)
			if len(idxs) != n {
				t.Fatalf("k=%d: got %d indices, want %d", k, len(idxs), n)
			}
			for want, got := range idxs {
				if got != want+1 {
					t.Fatalf("k=%d: index[%d]=%d, want %d", k, want, got, want+1)
				}
			}
		}
	})
}
