package command

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kr/text"
	"github.com/ryanuber/columnize"
)

// columnOuput prints the list of items as a table with no headers.
func columnOutput(list []string, c *columnize.Config) string {
	if len(list) == 0 {
		return ""
	}

	if c == nil {
		c = &columnize.Config{}
	}
	if c.Glue == "" {
		c.Glue = "    "
	}
	if c.Empty == "" {
		c.Empty = "n/a"
	}

	return columnize.Format(list, c)
}

// tableOutput prints the list of items as columns, where the first row is
// the list of headers.
func tableOutput(list []string, c *columnize.Config) string {
	if len(list) == 0 {
		return ""
	}

	delim := "|"
	if c != nil && c.Delim != "" {
		delim = c.Delim
	}

	underline := ""
	headers := strings.Split(list[0], delim)
	for i, h := range headers {
		h = strings.TrimSpace(h)
		u := strings.Repeat("-", len(h))

		underline = underline + u
		if i != len(headers)-1 {
			underline = underline + delim
		}
	}

	list = append(list, "")
	copy(list[2:], list[1:])
	list[1] = underline

	return columnOutput(list, c)
}

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

// humanDuration prints the time duration without those pesky zeros.
func humanDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}

	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if idx := strings.Index(s, "h0m"); idx > 0 {
		s = s[:idx+1] + s[idx+3:]
	}
	return s
}

// humanDurationInt prints the given int as if it were a time.Duration  number
// of seconds.
func humanDurationInt(i interface{}) interface{} {
	switch i := i.(type) {
	case int:
		return humanDuration(time.Duration(i) * time.Second)
	case int64:
		return humanDuration(time.Duration(i) * time.Second)
	case json.Number:
		if i, err := i.Int64(); err == nil {
			return humanDuration(time.Duration(i) * time.Second)
		}
	}

	// If we don't know what type it is, just return the original value
	return i
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

func generateFlagErrors(f *FlagSets, opts ...ParseOptions) error {
	return nil
}
