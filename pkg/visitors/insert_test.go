// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"os"
	"strings"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

const (
	insertTestFile = "../../integration/roms/testfile.ffs"
)

func testRunObsoleteInsert(t *testing.T, f uefi.Firmware, insertType InsertType, testGUID guid.GUID) (*Insert, error) {
	file, err := os.ReadFile(insertTestFile)
	if err != nil {
		t.Fatal(err)
	}

	ffs, err := uefi.NewFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// Apply the visitor.
	var pred FindPredicate
	if insertType == InsertTypeDXE {
		pred = FindFileTypePredicate(uefi.FVFileTypeDXECore)
	} else {
		pred = FindFileGUIDPredicate(testGUID)
	}
	insert := &Insert{
		Predicate:  pred,
		NewFile:    ffs,
		InsertType: insertType,
	}

	return insert, insert.Run(f)
}

func TestObsoleteInsert(t *testing.T) {
	var tests = []struct {
		name string
		InsertType
	}{
		{InsertTypeFront.String(), InsertTypeFront},
		{InsertTypeEnd.String(), InsertTypeEnd},
		{InsertTypeAfter.String(), InsertTypeAfter},
		{InsertTypeBefore.String(), InsertTypeBefore},
		{InsertTypeDXE.String(), InsertTypeDXE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := parseImage(t)

			_, err := testRunObsoleteInsert(t, f, test.InsertType, *testGUID)
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

func testInsertCLI(t *testing.T, whatType InsertWhatType, wherePreposition InsertWherePreposition) {
	f := parseImage(t)

	args := []string{
		whatType.String(),
	}
	switch whatType {
	case InsertWhatTypeFile:
		args = append(args, insertTestFile)
	case InsertWhatTypePadFile:
		args = append(args, "256")
	default:
		t.Fatalf("unknown what-type '%s'", whatType)
	}

	args = append(args, wherePreposition.String(), testGUID.String())

	visitor, err := genInsertFileCLI()(args)
	if err != nil {
		t.Fatal(err)
	}

	if err := visitor.Run(f); err != nil {
		t.Fatal(err)
	}

	switch whatType {
	case InsertWhatTypeFile:
		find := &Find{
			Predicate: FindFileGUIDPredicate(*testGUID),
		}
		if err = find.Run(f); err != nil {
			t.Fatal(err)
		}
		if len(find.Matches) != 2 {
			t.Errorf("incorrect number of matches after insertion! expected 2, got %v", len(find.Matches))
		}
	case InsertWhatTypePadFile:
		find := &Find{
			Predicate: func(f uefi.Firmware) bool {
				file, ok := f.(*uefi.File)
				if !ok {
					return false
				}
				if file.Header.GUID.String() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
					return false
				}
				if len(file.Buf()) != 256 {
					return false
				}
				return true
			},
		}
		if err = find.Run(f); err != nil {
			t.Fatal(err)
		}
		if len(find.Matches) != 1 {
			t.Errorf("incorrect number of matches after insertion! expected 1, got %v", len(find.Matches))
		}
	default:
		t.Fatalf("unknown what-type '%s'", whatType)
	}
}

func TestInsert(t *testing.T) {
	for whatType := InsertWhatTypeUndefined + 1; whatType < EndOfInsertWhatType; whatType++ {
		t.Run(whatType.String(), func(t *testing.T) {
			for wherePreposition := InsertWherePrepositionUndefined + 1; wherePreposition < EndOfInsertWherePreposition; wherePreposition++ {
				t.Run(wherePreposition.String(), func(t *testing.T) {
					testInsertCLI(t, whatType, wherePreposition)
				})
			}
		})
	}
}

func TestDoubleFindInsert(t *testing.T) {
	var tests = []struct {
		name string
		InsertType
	}{
		{"insert_after double result", InsertTypeAfter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := parseImage(t)

			insert, err := testRunObsoleteInsert(t, f, test.InsertType, *testGUID)
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
		{"insert_after no file", InsertTypeAfter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := parseImage(t)

			_, err := testRunObsoleteInsert(t, f, test.InsertType,
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
