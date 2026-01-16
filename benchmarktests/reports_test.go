// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package benchmarktests

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestReportJSONRoundTrip(t *testing.T) {
	const TEST_JSON = `{"metrics":{"kvv2_read_test":{"latencies":{"total":7157696803,"mean":6566694,"50th":2864535,"90th":18211907,"95th":23284373,"99th":30921207,"max":41417781,"min":836338},"bytes_in":{"total":356323,"mean":326.90183486238533},"bytes_out":{"total":0,"mean":0},"earliest":"2024-11-26T00:26:05.016666748Z","latest":"2024-11-26T00:26:25.003252391Z","end":"2024-11-26T00:26:25.013619962Z","duration":19986585643,"wait":10367571,"requests":1090,"rate":54.53657865678303,"throughput":54.5083037568385,"success":1,"status_codes":{"200":1090},"errors":[]},"kvv2_write_test":{"latencies":{"total":7971712798,"mean":7286757,"50th":3696355,"90th":18984537,"95th":22875811,"99th":31078756,"max":40748225,"min":1332091},"bytes_in":{"total":325939,"mean":297.93327239488116},"bytes_out":{"total":1116974,"mean":1021},"earliest":"2024-11-26T00:26:05.025865367Z","latest":"2024-11-26T00:26:25.013622375Z","end":"2024-11-26T00:26:25.023812123Z","duration":19987757008,"wait":10189748,"requests":1094,"rate":54.733505093249434,"throughput":54.705616198911336,"success":1,"status_codes":{"200":1094},"errors":[]},"total":{"latencies":{"total":200292508390,"mean":46267615,"50th":36803887,"90th":94118063,"95th":100149592,"99th":112306784,"max":148970336,"min":836338},"bytes_in":{"total":1926362,"mean":444.99006699006696},"bytes_out":{"total":1168454,"mean":269.9131439131439},"earliest":"2024-11-26T00:26:05.016666748Z","latest":"2024-11-26T00:26:25.022994974Z","end":"2024-11-26T00:26:25.090028301Z","duration":20006328226,"wait":67033327,"requests":4329,"rate":216.38153443739267,"throughput":215.65894623927713,"success":1,"status_codes":{"200":4329},"errors":[]},"userpass_test1":{"latencies":{"total":185163098789,"mean":86323122,"50th":84797535,"90th":100201564,"95th":104858591,"99th":118494024,"max":148970336,"min":67033327},"bytes_in":{"total":1244100,"mean":580},"bytes_out":{"total":51480,"mean":24},"earliest":"2024-11-26T00:26:05.016769036Z","latest":"2024-11-26T00:26:25.022994974Z","end":"2024-11-26T00:26:25.090028301Z","duration":20006225938,"wait":67033327,"requests":2145,"rate":107.2166237973834,"throughput":106.85858094505112,"success":1,"status_codes":{"200":2145},"errors":[]}},"target_addr":"http://localhost:8200"}`

	// Unmarshal
	reports, err := FromReader(strings.NewReader(TEST_JSON))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got: %d", len(reports))
	}
	if reports[0].clientAddr != "http://localhost:8200" {
		t.Fatalf("expected client address to be http://localhost:8200, got: %s", reports[0].clientAddr)
	}
	if len(reports[0].metrics) != 4 {
		t.Fatalf("expected 4 metrics, got: %d", len(reports[0].metrics))
	}
	if m, ok := reports[0].metrics["kvv2_read_test"]; ok {
		if m.Latencies.Total != 7157696803 {
			t.Fatalf("expected metric kvv2_read_test total to be 7157696803, got: %d", m.Latencies.Total)
		}
	} else {
		t.Fatalf("expected metric kvv2_read_test, got: %v", reports[0].metrics)
	}

	// Marshal
	var buf bytes.Buffer
	if err := reports[0].ReportJSON(&buf); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Unmarshal again
	reports2, err := FromReader(&buf)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !reflect.DeepEqual(reports, reports2) {
		t.Fatalf("expected reports to be unchanged after round trip: %v", reports2)
	}
}
