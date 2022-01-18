// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// InsertType defines the insert type operation that is requested
type InsertType int

// Insert Types
const (

	// == Deprectated ==

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

	// == Not deprecated ==

	// ReplaceFFS replaces the found file with the new FFS. This is used
	// as a shortcut for remove and insert combined, but also when we want to make
	// sure that the starting offset of the new file is the same as the old.
	ReplaceFFS
	// TODO: Add InsertIn

	// Insert is generalization of all Insert* above. Arguments:
	// * The first argument specifies the type of what to insert (possible values: "file" or "pad_file")
	// * The second argument specifies the content of what to insert:
	//     - If the first argument is "file" then a path to the file content is expected.
	//     - If the first argument is "pad_file" then the size is expected.
	// * The third argument specifies the preposition of where to insert to (possible values: "front", "end", "after", "before").
	// * The forth argument specifies the preposition object of where to insert to. It could be FV_or_File GUID_or_name.
	//   For example combination "end 5C60F367-A505-419A-859E-2A4FF6CA6FE5" means to insert to the end of volume
	//   "5C60F367-A505-419A-859E-2A4FF6CA6FE5".
	//
	// A complete example: "pad_file 256 after FC510EE7-FFDC-11D4-BD41-0080C73C8881" means to insert a pad file
	// of size 256 bytes after file with GUID "FC510EE7-FFDC-11D4-BD41-0080C73C8881".
	Insert
)

var insertTypeNames = map[InsertType]string{
	Insert:     "insert",
	ReplaceFFS: "replace_ffs",

	// Deprecated:
	InsertFront:  "insert_front",
	InsertEnd:    "insert_end",
	InsertAfter:  "insert_after",
	InsertBefore: "insert_before",
	InsertDXE:    "insert_dxe",
}

// String creates a string representation for the insert type.
func (i InsertType) String() string {
	if t, ok := insertTypeNames[i]; ok {
		return t
	}
	return "UNKNOWN"
}

// InsertWhatType defines the type of inserting object
type InsertWhatType int

const (
	InsertWhatTypeUndefined = InsertWhatType(iota)
	InsertWhatTypeFile
	InsertWhatTypePadFile

	EndOfInsertWhatType
)

// String implements fmt.Stringer.
func (t InsertWhatType) String() string {
	switch t {
	case InsertWhatTypeUndefined:
		return "undefined"
	case InsertWhatTypeFile:
		return "file"
	case InsertWhatTypePadFile:
		return "pad_file"
	}
	return fmt.Sprintf("unknown_%d", t)
}

// ParseInsertWhatType converts a string to InsertWhatType
func ParseInsertWhatType(s string) InsertWhatType {
	// TODO: it is currently O(n), optimize

	s = strings.Trim(strings.ToLower(s), " \t")
	for t := InsertWhatTypeUndefined; t < EndOfInsertWhatType; t++ {
		if t.String() == s {
			return t
		}
	}
	return InsertWhatTypeUndefined
}

// InsertWherePreposition defines the type of inserting object
type InsertWherePreposition int

const (
	InsertWherePrepositionUndefined = InsertWherePreposition(iota)
	InsertWherePrepositionFront
	InsertWherePrepositionEnd
	InsertWherePrepositionAfter
	InsertWherePrepositionBefore

	EndOfInsertWherePreposition
)

// String implements fmt.Stringer.
func (p InsertWherePreposition) String() string {
	switch p {
	case InsertWherePrepositionUndefined:
		return "undefined"
	case InsertWherePrepositionFront:
		return "front"
	case InsertWherePrepositionEnd:
		return "end"
	case InsertWherePrepositionAfter:
		return "after"
	case InsertWherePrepositionBefore:
		return "before"
	}
	return fmt.Sprintf("unknown_%d", p)
}

// ParseInsertWherePreposition converts a string to InsertWherePreposition
func ParseInsertWherePreposition(s string) InsertWherePreposition {
	// TODO: it is currently O(n), optimize

	s = strings.Trim(strings.ToLower(s), " \t")
	for t := InsertWherePrepositionUndefined; t < EndOfInsertWherePreposition; t++ {
		if t.String() == s {
			return t
		}
	}
	return InsertWherePrepositionUndefined
}

// Inserter inserts a firmware file into an FV
type Inserter struct {
	// TODO: use InsertWherePreposition to define the location, instead of InsertType

	// Input
	Predicate func(f uefi.Firmware) bool
	NewFile   *uefi.File
	InsertType

	// Matched File
	FileMatch uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Inserter) Run(f uefi.Firmware) error {
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
func (v *Inserter) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FirmwareVolume:
		for i := 0; i < len(f.Files); i++ {
			if f.Files[i] == v.FileMatch {
				// TODO: use InsertWherePreposition to define the location, instead of InsertType
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

func parseFile(filePath string) (*uefi.File, error) {
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read file '%s': %w", filePath, err)
	}

	file, err := uefi.NewFile(fileBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse file '%s': %w", filePath, err)
	}

	return file, nil
}

func genInsertRegularFileCLI(iType InsertType) func(args []string) (uefi.Visitor, error) {
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

		file, err := parseFile(filename)
		if err != nil {
			return nil, fmt.Errorf("unable to parse file '%s': %w", args[1], err)
		}

		// Insert File.
		return &Inserter{
			Predicate:  pred,
			NewFile:    file,
			InsertType: iType,
		}, nil
	}
}

func genInsertFileCLI() func(args []string) (uefi.Visitor, error) {
	return func(args []string) (uefi.Visitor, error) {
		whatType := ParseInsertWhatType(args[0])
		if whatType == InsertWhatTypeUndefined {
			return nil, fmt.Errorf("unknown what-type: '%s'", args[0])
		}

		var file *uefi.File
		switch whatType {
		case InsertWhatTypeFile:
			var err error
			file, err = parseFile(args[1])
			if err != nil {
				return nil, fmt.Errorf("unable to parse file '%s': %w", args[1], err)
			}
		case InsertWhatTypePadFile:
			padSize, err := strconv.ParseUint(args[1], 0, 64)
			if err != nil {
				return nil, fmt.Errorf("unable to parse pad file size '%s': %w", args[1], err)
			}
			file, err = uefi.CreatePadFile(padSize)
			if err != nil {
				return nil, fmt.Errorf("unable to create a pad file of size %d: %w", padSize, err)
			}
		default:
			return nil, fmt.Errorf("what-type '%s' is not supported, yet", whatType)
		}

		wherePreposition := ParseInsertWherePreposition(args[2])
		if wherePreposition == InsertWherePrepositionUndefined {
			return nil, fmt.Errorf("unknown where-preposition: '%s'", args[2])
		}

		pred, err := FindFileFVPredicate(args[3])
		if err != nil {
			return nil, fmt.Errorf("unable to parse the predicate parameters '%s': %w", args[0], err)
		}

		// TODO: use InsertWherePreposition to define the location, instead of InsertType
		var insertType InsertType
		switch wherePreposition {
		case InsertWherePrepositionFront:
			insertType = InsertFront
		case InsertWherePrepositionEnd:
			insertType = InsertEnd
		case InsertWherePrepositionAfter:
			insertType = InsertAfter
		case InsertWherePrepositionBefore:
			insertType = InsertBefore
		default:
			return nil, fmt.Errorf("where-preposition '%s' is not supported, yet", wherePreposition)
		}

		// Insert File.
		return &Inserter{
			Predicate: pred,
			NewFile:   file,
			// TODO: use InsertWherePreposition to define the location, instead of InsertType
			InsertType: insertType,
		}, nil
	}
}

func init() {
	RegisterCLI(insertTypeNames[Insert],
		"insert a file", 4, genInsertFileCLI())
	RegisterCLI(insertTypeNames[ReplaceFFS],
		"replace a file with another file", 2, genInsertRegularFileCLI(ReplaceFFS))
	RegisterCLI(insertTypeNames[InsertFront],
		"(deprecated) insert a file at the beginning of a firmware volume", 2, genInsertRegularFileCLI(InsertFront))
	RegisterCLI(insertTypeNames[InsertEnd],
		"(deprecated) insert a file at the end of a firmware volume", 2, genInsertRegularFileCLI(InsertEnd))
	RegisterCLI(insertTypeNames[InsertDXE],
		"(deprecated) insert a file at the end of the DXE firmware volume", 1, genInsertRegularFileCLI(InsertDXE))
	RegisterCLI(insertTypeNames[InsertAfter],
		"(deprecated) insert a file after another file", 2, genInsertRegularFileCLI(InsertAfter))
	RegisterCLI(insertTypeNames[InsertBefore],
		"(deprecated) insert a file before another file", 2, genInsertRegularFileCLI(InsertBefore))
}
