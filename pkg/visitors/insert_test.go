// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

func testRunInsert(t *testing.T, f uefi.Firmware, insertType InsertType, testGUID guid.GUID) (*Insert, error) {
	file, err := ioutil.ReadFile("../../integration/roms/testfile.ffs")
	if err != nil {
		t.Fatal(err)
	}

	ffs, err := uefi.NewFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// Apply the visitor.
	insert := &Insert{
		Predicate:  FindFileGUIDPredicate(testGUID),
		NewFile:    ffs,
		InsertType: insertType,
	}

	return insert, insert.Run(f)
}

func TestInsert(t *testing.T) {
	var tests = []struct {
		name string
		InsertType
	}{
		{InsertFront.String(), InsertFront},
		{InsertEnd.String(), InsertEnd},
		{InsertAfter.String(), InsertAfter},
		{InsertBefore.String(), InsertBefore},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := parseImage(t)

			_, err := testRunInsert(t, f, test.InsertType, *testGUID)
			if err != nil {
				t.Fatal(err)
			}

			// Now check that f has two copies of testGUID (There was one, we inserted another).
			// TODO: Check for position in the future to make sure we actually insert where we want to.
			find := &Find{
				Predicate: FindFileGUIDPredicate(*testGUID),
			}
			if err = find.Run(f); err != nil {
				t.Fatal(err)
			}
			if len(find.Matches) != 2 {
				t.Errorf("Incorrect number of matches after insertion! expected 2, got %v", len(find.Matches))
			}
		})
	}
}

func TestDoubleFindInsert(t *testing.T) {
	var tests = []struct {
		name string
		InsertType
	}{
		{"insert_after double result", InsertAfter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := parseImage(t)

			insert, err := testRunInsert(t, f, test.InsertType, *testGUID)
			if err != nil {
				t.Fatal(err)
			}

			// Run it again, it should fail
			if err = insert.Run(f); err == nil {
				t.Fatal("Expected error, got nil.")
			}
			if !strings.HasPrefix(err.Error(), "more than one match, only one match allowed! got ") {
				t.Errorf("Mismatched error, got %v.", err.Error())
			}

		})
	}
}

func TestNoFindInsert(t *testing.T) {
	var tests = []struct {
		name string
		InsertType
	}{
		{"insert_after no file", InsertAfter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := parseImage(t)

			_, err := testRunInsert(t, f, test.InsertType,
				*guid.MustParse("DECAFBAD-0000-0000-0000-000000000000"))
			// It should fail due to no such file
			if err == nil {
				t.Fatal("Expected error, got nil.")
			}
			if err.Error() != "no matches found" {
				t.Errorf("Mismatched error, got %v.", err.Error())
			}

		})
	}
}
