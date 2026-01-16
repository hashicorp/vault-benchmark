// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package dockertest

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/go-uuid"
)

func editHCL(t *testing.T, file string, existing string, replace string) (func(), string) {
	input, err := os.ReadFile(file)
	if err != nil {
		t.Errorf("unable to read file (%s): %s", file, err.Error())
	}

	output := bytes.Replace(input, []byte(existing), []byte(replace), -1)

	i := len(file) - 4
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		t.Error("error generating UUID")
	}

	modifiedFileName := fmt.Sprintf("%s_%s_modified_%s", file[:i], uuid, file[i:])
	if err = os.WriteFile(modifiedFileName, output, 0666); err != nil {
		t.Errorf("unable to write (%s): %s", modifiedFileName, err.Error())
	}

	// cleanup of modified file
	cleanup := func() {
		err := os.Remove(modifiedFileName)
		if err != nil {
			t.Fatalf("Error removing file (%s): %s", modifiedFileName, err)
		}
	}

	return cleanup, modifiedFileName
}
