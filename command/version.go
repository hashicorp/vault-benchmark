package command

import (
	"strings"

	"github.com/hashicorp/vault-benchmark/version"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*VersionCommand)(nil)
	_ cli.CommandAutocomplete = (*VersionCommand)(nil)
)

// VersionCommand is a Command implementation prints the version.
type VersionCommand struct {
	*BaseCommand
}

func (c *VersionCommand) Synopsis() string {
	return "Prints the vault-benchmark version"
}

func (c *VersionCommand) Help() string {
	helpText := `
Usage: vault-benchmark version

  Prints the version of this vault-benchmark binary.

  Print the version:

      $ vault-benchmark version

  There are no arguments or flags to this command. Any additional arguments or
  flags are ignored.
`
	return strings.TrimSpace(helpText)
}

func (c *VersionCommand) Flags() *FlagSets {
	return nil
}

func (c *VersionCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *VersionCommand) AutocompleteFlags() complete.Flags {
	return nil
}

func (c *VersionCommand) Run(_ []string) int {
	out := version.GetHumanVersion()
	c.UI.Output(out)
	return 0
}
