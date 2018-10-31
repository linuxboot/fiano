// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"reflect"
	"testing"

	"github.com/linuxboot/fiano/pkg/uefi"
)

func TestReplacePE32(t *testing.T) {
	f := parseImage(t)

	// Apply the visitor.
	replace := &ReplacePE32{
		Predicate: FindFileGUIDPredicate(*testGUID),
		NewPE32:   []byte("MZbanana"),
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
	want := []byte{0x0c, 0x00, 0x00, byte(uefi.SectionTypePE32), 'M', 'Z', 'b', 'a', 'n', 'a', 'n', 'a'}
	file, ok := results[0].(*uefi.File)
	if !ok {
		t.Fatalf("did not match a file, got type :%T", file)
	}
	got := file.Sections[0].Buf()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want %v; got %v", want, got)
	}
}

func TestErrors(t *testing.T) {
	f := parseImage(t)

	var tests = []struct {
		name    string
		newPE32 []byte
		match   string
		err     string
	}{
		{"No Matches", []byte("MZbanana"), "no-match-string",
			"no matches found for replacement"},
		{"Multiple Matches", []byte("MZbanana"), ".*",
			"multiple matches found! There can be only one. Use find to list all matches"},
		{"Not PE32", []byte("banana"), ".*",
			"supplied binary is not a valid pe32 image"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Apply the visitor.
			pred, err := FindFilePredicate(test.match)
			if err != nil {
				t.Fatal(err)
			}
			replace := &ReplacePE32{
				Predicate: pred,
				NewPE32:   test.newPE32,
			}
			err = replace.Run(f)
			if err == nil {
				t.Fatalf("Expected Error (%v), got nil", test.err)
			} else if err.Error() != test.err {
				t.Fatalf("Mismatched Error: Expected %v, got %v", test.err, err.Error())
			}
		})
	}
}
