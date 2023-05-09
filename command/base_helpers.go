// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/kr/text"
)

// wrapAtLengthWithPadding wraps the given text at the maxLineLength, taking
// into account any provided left padding.
func wrapAtLengthWithPadding(s string, pad int) string {
	wrapped := text.Wrap(s, maxLineLength-pad)
	lines := strings.Split(wrapped, "\n")
	for i, line := range lines {
		lines[i] = strings.Repeat(" ", pad) + line
	}
	return strings.Join(lines, "\n")
}

func generateFlagWarnings(args []string) string {
	var trailingFlags []string
	for _, arg := range args {
		// "-" can be used where a file is expected to denote stdin.
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		trailingFlags = append(trailingFlags, arg)
	}

	if len(trailingFlags) > 0 {
		return fmt.Sprintf("Command flags must be provided before positional arguments. "+
			"The following arguments will not be parsed as flags: [%s]", strings.Join(trailingFlags, ","))
	} else {
		return ""
	}
}
