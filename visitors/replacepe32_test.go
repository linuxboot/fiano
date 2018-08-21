// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"reflect"
	"testing"

	"github.com/linuxboot/fiano/uefi"
)

func TestReplacePE32(t *testing.T) {
	f := parseImage(t)

	// Apply the visitor.
	replace := &ReplacePE32{
		Predicate: func(f *uefi.File, name string) bool {
			return f.Header.UUID == *testGUID
		},
		NewPE32: []byte("banana"),
	}
	if err := replace.Run(f); err != nil {
		t.Fatal(err)
	}

	// We expect one match.
	if len(replace.Matches) != 1 {
		t.Fatalf("got %d matches; expected 1", len(replace.Matches))
	}

	// Find the section and make sure it contains the expected data.
	results := find(t, f, testGUID)
	if len(results) != 1 {
		t.Fatalf("got %d matches; expected 1", len(results))
	}
	want := []byte{0x0a, 0x00, 0x00, byte(uefi.SectionTypePE32), 'b', 'a', 'n', 'a', 'n', 'a'}
	got := results[0].Sections[0].Buf
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want %v; got %v", want, got)
	}
}
