package visitors

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestJSON tests the JSON visitor. The amount of testing is negligible. This
// simply tests that valid ROMs produce valid JSON.
func TestJSON(t *testing.T) {
	f := parseImage(t)

	out := &bytes.Buffer{}
	jason := &JSON{
		W: out,
	}

	if err := f.Apply(jason); err != nil {
		t.Fatal(err)
	}

	var dec interface{}
	if err := json.Unmarshal(out.Bytes(), &dec); err != nil {
		t.Errorf("invalid json: %q", out.String())
	}
}
