// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/hashicorp/vault/api"
	"github.com/mattn/go-colorable"
	"github.com/mitchellh/cli"
)

var commonCommands = []string{
	"run",
	"review",
}

type VaultUI struct {
	cli.Ui
	format   string
	detailed bool
}

type RunOptions struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Address string
	Client  *api.Client
}

func Run(args []string) int {
	return RunCustom(args, nil)
}

// RunCustom allows passing in a base command template to pass to other
// commands. Currently, this is only used for setting a custom token helper.
func RunCustom(args []string, runOpts *RunOptions) int {
	for _, arg := range args {
		if len(args) == 1 && (arg == "-v" || arg == "-version" || arg == "--version") {
			args = []string{"version"}
			break
		}
	}
	if runOpts == nil {
		runOpts = &RunOptions{}
	}
	var format string
	var detailed bool

	// Don't use color if disabled
	useColor := true

	if runOpts.Stdout == nil {
		runOpts.Stdout = os.Stdout
	}
	if runOpts.Stderr == nil {
		runOpts.Stderr = os.Stderr
	}

	// Only use colored UI if stdout is a tty, and not disabled
	if useColor && format == "table" {
		if f, ok := runOpts.Stdout.(*os.File); ok {
			runOpts.Stdout = colorable.NewColorable(f)
		}
		if f, ok := runOpts.Stderr.(*os.File); ok {
			runOpts.Stderr = colorable.NewColorable(f)
		}
	} else {
		runOpts.Stdout = colorable.NewNonColorable(runOpts.Stdout)
		runOpts.Stderr = colorable.NewNonColorable(runOpts.Stderr)
	}

	uiErrWriter := runOpts.Stderr

	ui := &VaultUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      runOpts.Stdout,
				ErrorWriter: uiErrWriter,
			},
		},
		format:   format,
		detailed: detailed,
	}

	commands := map[string]cli.CommandFactory{
		"run": func() (cli.Command, error) {
			return &RunCommand{
				BaseCommand: &BaseCommand{
					UI: ui,
				},
			}, nil
		},
		"review": func() (cli.Command, error) {
			return &ReviewCommand{
				BaseCommand: &BaseCommand{
					UI: ui,
				},
			}, nil
		},
		"version": func() (cli.Command, error) {
			return &VersionCommand{
				BaseCommand: &BaseCommand{
					UI: ui,
				},
			}, nil
		},
	}

	hiddenCommands := []string{"version"}

	cli := &cli.CLI{
		Name:     "vault-benchmark",
		Args:     args,
		Commands: commands,
		HelpFunc: groupedHelpFunc(
			cli.BasicHelpFunc("vault-benchmark"),
		),
		HelpWriter:                 runOpts.Stdout,
		ErrorWriter:                runOpts.Stderr,
		HiddenCommands:             hiddenCommands,
		Autocomplete:               true,
		AutocompleteNoDefaultFlags: true,
	}

	exitCode, err := cli.Run()
	if err != nil {
		fmt.Fprintf(runOpts.Stderr, "Error executing CLI: %s\n", err.Error())
		return 1
	}

	return exitCode
}

func groupedHelpFunc(f cli.HelpFunc) cli.HelpFunc {
	return func(commands map[string]cli.CommandFactory) string {
		var b bytes.Buffer
		tw := tabwriter.NewWriter(&b, 0, 2, 6, ' ', 0)

		fmt.Fprintf(tw, "Usage: vault-benchmark <command> [args]\n\n")
		fmt.Fprintf(tw, "Command list:\n")
		for _, v := range commonCommands {
			printCommand(tw, v, commands[v])
		}

		otherCommands := make([]string, 0, len(commands))
		for k := range commands {
			found := false
			for _, v := range commonCommands {
				if k == v {
					found = true
					break
				}
			}

			if !found {
				otherCommands = append(otherCommands, k)
			}
		}

		sort.Strings(otherCommands)

		fmt.Fprintf(tw, "\n")
		tw.Flush()

		return strings.TrimSpace(b.String())
	}
}

func printCommand(w io.Writer, name string, cmdFn cli.CommandFactory) {
	cmd, err := cmdFn()
	if err != nil {
		log.Fatalf(fmt.Sprintf("failed to load %q command: %s", name, err))
	}
	fmt.Fprintf(w, "    %s\t%s\n", name, cmd.Synopsis())
}
