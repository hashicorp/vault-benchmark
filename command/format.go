package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/cli"
	"github.com/ryanuber/columnize"
)

const (
	// hopeDelim is the delimiter to use when splitting columns. We call it a
	// hopeDelim because we hope that it's never contained in a secret.
	hopeDelim = "♨"
)

type FormatOptions struct {
	Format string
}

func OutputSecret(ui cli.Ui, secret *api.Secret) int {
	return outputWithFormat(ui, secret, secret)
}

func OutputList(ui cli.Ui, data interface{}) int {
	switch data := data.(type) {
	case *api.Secret:
		secret := data
		return outputWithFormat(ui, secret, secret.Data["keys"])
	default:
		return outputWithFormat(ui, nil, data)
	}
}

func OutputData(ui cli.Ui, data interface{}) int {
	return outputWithFormat(ui, nil, data)
}

func outputWithFormat(ui cli.Ui, secret *api.Secret, data interface{}) int {
	format := Format(ui)
	formatter, ok := Formatters[format]
	if !ok {
		ui.Error(fmt.Sprintf("Invalid output format: %s", format))
		return 1
	}

	if err := formatter.Output(ui, secret, data); err != nil {
		ui.Error(fmt.Sprintf("Could not parse output: %s", err.Error()))
		return 1
	}
	return 0
}

type Formatter interface {
	Output(ui cli.Ui, secret *api.Secret, data interface{}) error
	Format(data interface{}) ([]byte, error)
}

var Formatters = map[string]Formatter{
	"json":   JsonFormatter{},
	"table":  TableFormatter{},
	"yaml":   YamlFormatter{},
	"yml":    YamlFormatter{},
	"pretty": PrettyFormatter{},
	"raw":    RawFormatter{},
}

func Format(ui cli.Ui) string {
	switch ui := ui.(type) {
	case *VaultUI:
		return ui.format
	}

	format := "table"

	return format
}

func Detailed(ui cli.Ui) bool {
	switch ui := ui.(type) {
	case *VaultUI:
		return ui.detailed
	}

	return false
}

// An output formatter for json output of an object
type JsonFormatter struct{}

func (j JsonFormatter) Format(data interface{}) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

func (j JsonFormatter) Output(ui cli.Ui, secret *api.Secret, data interface{}) error {
	b, err := j.Format(data)
	if err != nil {
		return err
	}

	if secret != nil {
		shouldListWithInfo := Detailed(ui)

		// Show the raw JSON of the LIST call, rather than only the
		// list of keys.
		if shouldListWithInfo {
			b, err = j.Format(secret)
			if err != nil {
				return err
			}
		}
	}

	ui.Output(string(b))
	return nil
}

// An output formatter for raw output of the original request object
type RawFormatter struct{}

func (r RawFormatter) Format(data interface{}) ([]byte, error) {
	byte_data, ok := data.([]byte)
	if !ok {
		return nil, fmt.Errorf("This command does not support the -format=raw option; only `vault read` does.")
	}

	return byte_data, nil
}

func (r RawFormatter) Output(ui cli.Ui, secret *api.Secret, data interface{}) error {
	b, err := r.Format(data)
	if err != nil {
		return err
	}
	ui.Output(string(b))
	return nil
}

// An output formatter for yaml output format of an object
type YamlFormatter struct{}

func (y YamlFormatter) Format(data interface{}) ([]byte, error) {
	return yaml.Marshal(data)
}

func (y YamlFormatter) Output(ui cli.Ui, secret *api.Secret, data interface{}) error {
	b, err := y.Format(data)
	if err == nil {
		ui.Output(strings.TrimSpace(string(b)))
	}
	return err
}

type PrettyFormatter struct{}

func (p PrettyFormatter) Format(data interface{}) ([]byte, error) {
	return nil, nil
}

func (p PrettyFormatter) Output(ui cli.Ui, secret *api.Secret, data interface{}) error {
	switch data.(type) {
	default:
		return errors.New("cannot use the pretty formatter for this type")
	}
	return nil
}

func outputStringSlice(buffer *bytes.Buffer, indent string, values []string) {
	for _, val := range values {
		buffer.WriteString(fmt.Sprintf("%s%s\n", indent, val))
	}
}

type mapOutput struct {
	key   string
	value string
}

// An output formatter for table output of an object
type TableFormatter struct{}

// We don't use this due to the TableFormatter introducing a bug when the -field flag is supplied:
// https://github.com/hashicorp/vault/commit/b24cf9a8af2190e96c614205b8cdf06d8c4b6718 .
func (t TableFormatter) Format(data interface{}) ([]byte, error) {
	return nil, nil
}

func (t TableFormatter) Output(ui cli.Ui, secret *api.Secret, data interface{}) error {
	switch data := data.(type) {
	case []interface{}:
		return t.OutputList(ui, secret, data)
	case []string:
		return t.OutputList(ui, nil, data)
	case map[string]interface{}:
		return t.OutputMap(ui, data)
	default:
		return errors.New("cannot use the table formatter for this type")
	}
}

func (t TableFormatter) OutputList(ui cli.Ui, secret *api.Secret, data interface{}) error {
	t.printWarnings(ui, secret)

	// Determine if we have additional information from a ListResponseWithInfo endpoint.
	var additionalInfo map[string]interface{}
	if secret != nil {
		shouldListWithInfo := Detailed(ui)
		if additional, ok := secret.Data["key_info"]; shouldListWithInfo && ok && len(additional.(map[string]interface{})) > 0 {
			additionalInfo = additional.(map[string]interface{})
		}
	}

	switch data := data.(type) {
	case []interface{}:
	case []string:
		ui.Output(tableOutput(data, nil))
		return nil
	default:
		return errors.New("error: table formatter cannot output list for this data type")
	}

	list := data.([]interface{})

	if len(list) > 0 {
		keys := make([]string, len(list))
		for i, v := range list {
			typed, ok := v.(string)
			if !ok {
				return fmt.Errorf("%v is not a string", v)
			}
			keys[i] = typed
		}
		sort.Strings(keys)

		// If we have a ListResponseWithInfo endpoint, we'll need to show
		// additional headers. To satisfy the table outputter, we'll need
		// to concat them with the deliminator.
		var headers []string
		header := "Keys"
		if len(additionalInfo) > 0 {
			seenHeaders := make(map[string]bool)
			for key, rawValues := range additionalInfo {
				// Most endpoints use the well-behaved ListResponseWithInfo.
				// However, some use a hand-rolled equivalent, where the
				// returned "keys" doesn't match the key of the "key_info"
				// member (namely, /sys/policies/egp). We seek to exclude
				// headers only visible from "non-visitable" key_info rows,
				// to make table output less confusing. These non-visitable
				// rows will still be visible in the JSON output.
				index := sort.SearchStrings(keys, key)
				if index < len(keys) && keys[index] != key {
					continue
				}

				values := rawValues.(map[string]interface{})
				for key := range values {
					seenHeaders[key] = true
				}
			}

			for key := range seenHeaders {
				headers = append(headers, key)
			}
			sort.Strings(headers)

			header = header + hopeDelim + strings.Join(headers, hopeDelim)
		}

		// Finally, if we have a ListResponseWithInfo, we'll need to update
		// the returned rows to not just have the keys (in the sorted order),
		// but also have the values for each header (in their sorted order).
		rows := keys
		if len(additionalInfo) > 0 && len(headers) > 0 {
			for index, row := range rows {
				formatted := []string{row}
				if rawValues, ok := additionalInfo[row]; ok {
					values := rawValues.(map[string]interface{})
					for _, header := range headers {
						if rawValue, ok := values[header]; ok {
							if looksLikeDuration(header) {
								rawValue = humanDurationInt(rawValue)
							}

							formatted = append(formatted, fmt.Sprintf("%v", rawValue))
						} else {
							// Show a default empty n/a when this field is
							// missing from the additional information.
							formatted = append(formatted, "n/a")
						}
					}
				}

				rows[index] = strings.Join(formatted, hopeDelim)
			}
		}

		// Prepend the header to the formatted rows.
		output := append([]string{header}, rows...)
		ui.Output(tableOutput(output, &columnize.Config{
			Delim: hopeDelim,
		}))
	}

	return nil
}

// printWarnings prints any warnings in the secret.
func (t TableFormatter) printWarnings(ui cli.Ui, secret *api.Secret) {
	if secret != nil && len(secret.Warnings) > 0 {
		ui.Warn("WARNING! The following warnings were returned from Vault:\n")
		for _, warning := range secret.Warnings {
			ui.Warn(wrapAtLengthWithPadding(fmt.Sprintf("* %s", warning), 2))
			ui.Warn("")
		}
	}
}

func (t TableFormatter) OutputMap(ui cli.Ui, data map[string]interface{}) error {
	out := make([]string, 0, len(data)+1)
	if len(data) > 0 {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			v := data[k]

			// If the field "looks" like a TTL, print it as a time duration instead.
			if looksLikeDuration(k) {
				v = humanDurationInt(v)
			}

			out = append(out, fmt.Sprintf("%s %s %v", k, hopeDelim, v))
		}
	}

	// If we got this far and still don't have any data, there's nothing to print,
	// sorry.
	if len(out) == 0 {
		return nil
	}

	// Prepend the header
	out = append([]string{"Key" + hopeDelim + "Value"}, out...)

	ui.Output(tableOutput(out, &columnize.Config{
		Delim: hopeDelim,
	}))
	return nil
}

// OutputSealStatus will print *api.SealStatusResponse in the CLI according to the format provided
func OutputSealStatus(ui cli.Ui, client *api.Client, status *api.SealStatusResponse) int {
	sealStatusOutput := SealStatusOutput{SealStatusResponse: *status}

	// Mask the 'Vault is sealed' error, since this means HA is enabled, but that
	// we cannot query for the leader since we are sealed.
	leaderStatus, err := client.Sys().Leader()
	if err != nil && strings.Contains(err.Error(), "Vault is sealed") {
		leaderStatus = &api.LeaderResponse{HAEnabled: true}
		err = nil
	}
	if err != nil {
		ui.Error(fmt.Sprintf("Error checking leader status: %s", err))
		return 1
	}

	// copy leaderStatus fields into sealStatusOutput for display later
	sealStatusOutput.HAEnabled = leaderStatus.HAEnabled
	sealStatusOutput.IsSelf = leaderStatus.IsSelf
	sealStatusOutput.ActiveTime = leaderStatus.ActiveTime
	sealStatusOutput.LeaderAddress = leaderStatus.LeaderAddress
	sealStatusOutput.LeaderClusterAddress = leaderStatus.LeaderClusterAddress
	sealStatusOutput.PerfStandby = leaderStatus.PerfStandby
	sealStatusOutput.PerfStandbyLastRemoteWAL = leaderStatus.PerfStandbyLastRemoteWAL
	sealStatusOutput.LastWAL = leaderStatus.LastWAL
	sealStatusOutput.RaftCommittedIndex = leaderStatus.RaftCommittedIndex
	sealStatusOutput.RaftAppliedIndex = leaderStatus.RaftAppliedIndex
	OutputData(ui, sealStatusOutput)
	return 0
}

// looksLikeDuration checks if the given key "k" looks like a duration value.
// This is used to pretty-format duration values in responses, especially from
// plugins.
func looksLikeDuration(k string) bool {
	return k == "period" || strings.HasSuffix(k, "_period") ||
		k == "ttl" || strings.HasSuffix(k, "_ttl") ||
		k == "duration" || strings.HasSuffix(k, "_duration") ||
		k == "lease_max" || k == "ttl_max"
}

// This struct is responsible for capturing all the fields to be output by a
// vault status command, including fields that do not come from the status API.
// Currently we are adding the fields from api.LeaderResponse
type SealStatusOutput struct {
	api.SealStatusResponse
	HAEnabled                bool      `json:"ha_enabled"`
	IsSelf                   bool      `json:"is_self,omitempty"`
	ActiveTime               time.Time `json:"active_time,omitempty"`
	LeaderAddress            string    `json:"leader_address,omitempty"`
	LeaderClusterAddress     string    `json:"leader_cluster_address,omitempty"`
	PerfStandby              bool      `json:"performance_standby,omitempty"`
	PerfStandbyLastRemoteWAL uint64    `json:"performance_standby_last_remote_wal,omitempty"`
	LastWAL                  uint64    `json:"last_wal,omitempty"`
	RaftCommittedIndex       uint64    `json:"raft_committed_index,omitempty"`
	RaftAppliedIndex         uint64    `json:"raft_applied_index,omitempty"`
}
