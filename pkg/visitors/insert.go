// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// InsertType defines the insert type operation that is requested
type InsertType int

// Insert Types
const (
	// These first two specify a firmware volume.

	// InsertFront inserts a file at the beginning of the firmware volume,
	// which is specified by 1) FVname GUID, or (File GUID/File name) of a file
	// inside that FV.
	InsertFront InsertType = iota
	// InsertEnd inserts a file at the end of the specified firmware volume.
	InsertEnd

	// These two specify a File to insert before or after
	// InsertAfter inserts after the specified file,
	// which is specified by a File GUID or File name.
	InsertAfter
	// InsertBefore inserts before the specified file.
	InsertBefore
	// InsertDXE inserts into the Dxe Firmware Volume. This works by searching
	// for the DxeCore first to identify the Dxe Firmware Volume.
	InsertDXE

	// ReplaceFFS replaces the found file with the new FFS. This is used
	// as a shortcut for remove and insert combined, but also when we want to make
	// sure that the starting offset of the new file is the same as the old.
	ReplaceFFS
	// TODO: Add InsertIn
)

var insertTypeNames = map[InsertType]string{
	InsertFront:  "insert_front",
	InsertEnd:    "insert_end",
	InsertAfter:  "insert_after",
	InsertBefore: "insert_before",
	InsertDXE:    "insert_dxe",
	ReplaceFFS:   "replace_ffs",
}

// String creates a string representation for the insert type.
func (i InsertType) String() string {
	if t, ok := insertTypeNames[i]; ok {
		return t
	}
	return "UNKNOWN"
}

// Insert inserts a firmware file into an FV
type Insert struct {
	// Input
	Predicate func(f uefi.Firmware) bool
	NewFile   *uefi.File
	InsertType

	// Matched File
	FileMatch uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Insert) Run(f uefi.Firmware) error {
	// First run "find" to generate a position to insert into.
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	if numMatch := len(find.Matches); numMatch > 1 {
		return fmt.Errorf("more than one match, only one match allowed! got %v", find.Matches)
	} else if numMatch == 0 {
		return errors.New("no matches found")
	}

	// Find should only match a file or a firmware volume. If it's an FV, we can
	// edit the FV directly.
	if fvMatch, ok := find.Matches[0].(*uefi.FirmwareVolume); ok {
		switch v.InsertType {
		case InsertFront:
			fvMatch.Files = append([]*uefi.File{v.NewFile}, fvMatch.Files...)
		case InsertEnd:
			fvMatch.Files = append(fvMatch.Files, v.NewFile)
		default:
			return fmt.Errorf("matched FV but insert operation was %s, which only matches Files",
				v.InsertType.String())
		}
		return nil
	}
	var ok bool
	if v.FileMatch, ok = find.Matches[0].(*uefi.File); !ok {
		return fmt.Errorf("match was not a file or a firmware volume: got %T, unable to insert", find.Matches[0])
	}
	// Match is a file, apply visitor.
	return f.Apply(v)
}

// Visit applies the Insert visitor to any Firmware type.
func (v *Insert) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FirmwareVolume:
		for i := 0; i < len(f.Files); i++ {
			if f.Files[i] == v.FileMatch {
				switch v.InsertType {
				case InsertFront:
					f.Files = append([]*uefi.File{v.NewFile}, f.Files...)
				case InsertDXE:
					fallthrough
				case InsertEnd:
					f.Files = append(f.Files, v.NewFile)
				case InsertAfter:
					f.Files = append(f.Files[:i+1], append([]*uefi.File{v.NewFile}, f.Files[i+1:]...)...)
				case InsertBefore:
					f.Files = append(f.Files[:i], append([]*uefi.File{v.NewFile}, f.Files[i:]...)...)
				case ReplaceFFS:
					f.Files = append(f.Files[:i], append([]*uefi.File{v.NewFile}, f.Files[i+1:]...)...)
				}
				return nil
			}
		}
	}

	return f.ApplyChildren(v)
}

func genInsertCLI(iType InsertType) func(args []string) (uefi.Visitor, error) {
	return func(args []string) (uefi.Visitor, error) {
		var pred FindPredicate
		var err error
		var filename string

		if iType == InsertDXE {
			pred = FindFileTypePredicate(uefi.FVFileTypeDXECore)
			filename = args[0]
		} else {
			pred, err = FindFileFVPredicate(args[0])
			if err != nil {
				return nil, err
			}
			filename = args[1]
		}

		newFileBuf, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		// Parse the file.
		file, err := uefi.NewFile(newFileBuf)
		if err != nil {
			return nil, err
		}

		// Insert File.
		return &Insert{
			Predicate:  pred,
			NewFile:    file,
			InsertType: iType,
		}, nil
	}
}

func init() {
	RegisterCLI(insertTypeNames[InsertFront],
		"insert a file at the beginning of a firmware volume", 2, genInsertCLI(InsertFront))
	RegisterCLI(insertTypeNames[InsertEnd],
		"insert a file at the end of a firmware volume", 2, genInsertCLI(InsertEnd))
	RegisterCLI(insertTypeNames[InsertDXE],
		"insert a file at the end of the DXE firmware volume", 1, genInsertCLI(InsertDXE))
	RegisterCLI(insertTypeNames[InsertAfter],
		"insert a file after another file", 2, genInsertCLI(InsertAfter))
	RegisterCLI(insertTypeNames[InsertBefore],
		"insert a file before another file", 2, genInsertCLI(InsertBefore))
	RegisterCLI(insertTypeNames[ReplaceFFS],
		"replace a file with another file", 2, genInsertCLI(ReplaceFFS))
}
