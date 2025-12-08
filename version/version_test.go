// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"testing"
)

func BenchmarkGetHumanVersion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetHumanVersion()
	}
}
