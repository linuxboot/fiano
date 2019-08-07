// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package guid2english

import (
	"bytes"
	"io"
	"testing"
	"text/template"

	"golang.org/x/text/transform"
)

func TestTransformer(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		tmpl   string
		output string
	}{
		{
			name:   "empty",
			input:  "",
			tmpl:   "",
			output: "",
		},
		{
			name:   "single GUID",
			input:  "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1",
			tmpl:   "{{.GUID}}",
			output: "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1",
		},
		{
			name:   "replace with name",
			input:  "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1",
			tmpl:   "{{.Name}}",
			output: "Shell",
		},
		{
			name:   "name and GUID",
			input:  "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1",
			tmpl:   "{{.GUID}} ({{.Name}})",
			output: "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1 (Shell)",
		},
		{
			name:   "unknown name and GUID",
			input:  "fff4A583-9E3E-4F1C-BD65-E05268D0B4D1",
			tmpl:   "{{.GUID}} ({{.Name}})",
			output: "FFF4A583-9E3E-4F1C-BD65-E05268D0B4D1 (UNKNOWN)",
		},
		{
			name:   "advanced formatting",
			input:  "fff4A583-9E3E-4F1C-BD65-E05268D0B4D1",
			tmpl:   "{{if .IsKnown}}KNOWN{{else}}UNKNOWN{{end}}",
			output: "UNKNOWN",
		},
		{
			name: "multiple GUIDs",
			input: `
Running 7C04A583-9E3E-4F1C-AD65-E05268D0B4D1...
Cannot find fff4A583-9E3E-4F1C-BD65-E05268D0B4D1...
Waiting for D5125E0F-1226-444F-A218-0085996ED5DA?
			`,
			tmpl: "{{.GUID}} ({{.Name}})",
			output: `
Running 7C04A583-9E3E-4F1C-AD65-E05268D0B4D1 (Shell)...
Cannot find FFF4A583-9E3E-4F1C-BD65-E05268D0B4D1 (UNKNOWN)...
Waiting for D5125E0F-1226-444F-A218-0085996ED5DA (Smbus)?
			`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.NewBufferString(tt.input)
			tmpl, err := template.New("guid2english").Parse(tt.tmpl)
			if err != nil {
				t.Fatalf("template not valid: %v", err)
			}

			trans := New(NewTemplateMapper(tmpl))

			output := &bytes.Buffer{}
			_, err = io.Copy(output, transform.NewReader(input, trans))
			if err != nil {
				t.Errorf("error copying buffer: %v", err)
			}

			if string(output.Bytes()) != tt.output {
				t.Errorf("got %q, want %q", output.Bytes(), tt.output)
			}
		})
	}
}
