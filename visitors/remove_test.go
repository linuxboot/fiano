package visitors

import (
	"testing"

	"github.com/linuxboot/fiano/uefi"
)

func TestRemove(t *testing.T) {
	f := parseImage(t)

	// Apply the visitor.
	remove := &Remove{
		Predicate: func(f *uefi.File, name string) bool {
			return f.Header.UUID == *testGUID
		},
	}
	if err := remove.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect no match.
	results := find(t, f, testGUID)
	if len(results) != 0 {
		t.Fatalf("got %d matches; expected 0", len(results))
	}
}
