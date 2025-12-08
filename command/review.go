// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault-benchmark/benchmarktests"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*ReviewCommand)(nil)
	_ cli.CommandAutocomplete = (*ReviewCommand)(nil)
)

type ReviewCommand struct {
	*BaseCommand
	flagReviewResultsFile string
	flagReportMode        string
}

func (r *ReviewCommand) Synopsis() string {
	return "Review previous test results"
}

func (r *ReviewCommand) Help() string {
	helpText := `
Usage: vault-benchmark review [options]

 This command prints previous JSON test results for review.

	$ vault-benchmark review -results_file=/etc/vault-benchmark/results.json

 For a full list of examples, please see the documentation.

` + r.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (r *ReviewCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (r *ReviewCommand) AutocompleteFlags() complete.Flags {
	return r.Flags().Completions()
}

func (r *ReviewCommand) Flags() *FlagSets {
	set := r.flagSet()
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:   "results_file",
		Target: &r.flagReviewResultsFile,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to a vault-benchmark test results file.",
	})

	f.StringVar(&StringVar{
		Name:    "report_mode",
		Target:  &r.flagReportMode,
		Default: "terse",
		Usage:   "Reporting Mode. Options are: terse, verbose, json.",
	})
	return set
}

func (r *ReviewCommand) Run(args []string) int {
	f := r.Flags()

	if err := f.Parse(args); err != nil {
		r.UI.Error(err.Error())
		return 1
	}

	// File Validity checking
	fStat, err := os.Stat(r.flagReviewResultsFile)
	if err != nil {
		r.UI.Error(fmt.Sprintf("error opening file: %v", err))
		return 1
	}

	if fStat.IsDir() {
		r.UI.Error("location is a directory, not a file")
		return 1
	}

	fReader, err := os.Open(r.flagReviewResultsFile)
	if err != nil {
		r.UI.Error(fmt.Sprintf("error opening file: %v", err))
		return 1
	}

	rpts, err := benchmarktests.FromReader(fReader)
	if err != nil {
		r.UI.Error(fmt.Sprintf("error reading report: %v", err))
		return 1
	}
	if len(rpts) == 0 {
		r.UI.Error("results file contains no valid reports")
		return 1
	}
	for _, rpt := range rpts {
		switch r.flagReportMode {
		case "json":
			err = fmt.Errorf("asked to report JSON on JSON input")
		case "verbose":
			err = rpt.ReportVerbose(os.Stdout)
		case "terse":
			err = rpt.ReportTerse(os.Stdout)
		}
		if err != nil {
			r.UI.Error(fmt.Sprintf("error writing report: %v", err))
			return 1
		}
	}
	return 0
}
