// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// FindPredicate is used to filter matches in the Find visitor.
type FindPredicate = func(f uefi.Firmware) bool

// Find a firmware file given its name or GUID.
type Find struct {
	// Input
	// Only when this functions returns true will the file appear in the
	// `Matches` slice.
	Predicate FindPredicate

	// Output
	Matches []uefi.Firmware

	// JSON is written to this writer.
	W io.Writer

	// Private
	currentFile *uefi.File
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Find) Run(f uefi.Firmware) error {
	if err := f.Apply(v); err != nil {
		return err
	}
	if v.W != nil {
		b, err := json.MarshalIndent(v.Matches, "", "\t")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(v.W, string(b))
	}
	return nil
}

// Visit applies the Find visitor to any Firmware type.
func (v *Find) Visit(f uefi.Firmware) error {
	switch f := f.(type) {

	case *uefi.File:
		// Clone the visitor so the `currentFile` is passed only to descendents.
		v2 := &Find{
			Predicate:   v.Predicate,
			currentFile: f,
		}

		if v.Predicate(f) {
			v.Matches = append(v.Matches, f)
			// Don't match with direct descendents.
			v2.currentFile = nil
		}

		err := f.ApplyChildren(v2)
		v.Matches = append(v.Matches, v2.Matches...) // Merge together
		return err

	case *uefi.Section:
		if v.currentFile != nil && v.Predicate(f) {
			v.Matches = append(v.Matches, v.currentFile)
			v.currentFile = nil // Do not double-match with a sibling if there are duplicate names.
		}
		return f.ApplyChildren(v)

	case *uefi.NVar:
		// don't find NVar embedded in NVar (TODO have a parameter for that ?)
		if v.Predicate(f) {
			v.Matches = append(v.Matches, f)
		}
		return nil

	default:
		if v.Predicate(f) {
			v.Matches = append(v.Matches, f)
		}
		return f.ApplyChildren(v)
	}
}

// FindFileGUIDPredicate is a generic predicate for searching file GUIDs only.
func FindFileGUIDPredicate(r guid.GUID) FindPredicate {
	return func(f uefi.Firmware) bool {
		if f, ok := f.(*uefi.File); ok {
			return f.Header.GUID == r
		}
		return false
	}
}

// FindFileTypePredicate is a generic predicate for searching file types only.
func FindFileTypePredicate(t uefi.FVFileType) FindPredicate {
	return func(f uefi.Firmware) bool {
		if f, ok := f.(*uefi.File); ok {
			return f.Header.Type == t
		}
		return false
	}
}

// FindFilePredicate is a generic predicate for searching files and UI sections only.
func FindFilePredicate(r string) (func(f uefi.Firmware) bool, error) {
	searchRE, err := regexp.Compile("^(" + r + ")$")
	if err != nil {
		return nil, err
	}
	ciRE, err := regexp.Compile("^(?i)(" + r + ")$")
	if err != nil {
		return nil, err
	}
	return func(f uefi.Firmware) bool {
		switch f := f.(type) {
		case *uefi.File:
			return ciRE.MatchString(f.Header.GUID.String())
		case *uefi.Section:
			return searchRE.MatchString(f.Name)
		}
		return false
	}, nil
}

// FindFileFVPredicate is a generic predicate for searching FVs, files and UI sections.
func FindFileFVPredicate(r string) (func(f uefi.Firmware) bool, error) {
	searchRE, err := regexp.Compile("^" + r + "$")
	if err != nil {
		return nil, err
	}
	ciRE, err := regexp.Compile("^(?i)" + r + "$")
	if err != nil {
		return nil, err
	}
	return func(f uefi.Firmware) bool {
		switch f := f.(type) {
		case *uefi.FirmwareVolume:
			return searchRE.MatchString(f.FVName.String())
		case *uefi.File:
			return ciRE.MatchString(f.Header.GUID.String())
		case *uefi.Section:
			return searchRE.MatchString(f.Name)
		}
		return false
	}, nil
}

// FindNotPredicate is a generic predicate which takes the logical NOT of an existing predicate.
func FindNotPredicate(predicate FindPredicate) FindPredicate {
	return func(f uefi.Firmware) bool {
		return !predicate(f)
	}
}

// FindAndPredicate is a generic predicate which takes the logical OR of two existing predicates.
func FindAndPredicate(predicate1 FindPredicate, predicate2 FindPredicate) FindPredicate {
	return func(f uefi.Firmware) bool {
		return predicate1(f) && predicate2(f)
	}
}

// FindExactlyOne does a find using a supplied predicate and errors if there's more than one.
func FindExactlyOne(f uefi.Firmware, pred func(f uefi.Firmware) bool) (uefi.Firmware, error) {
	find := &Find{
		Predicate: pred,
	}
	if err := find.Run(f); err != nil {
		return nil, err
	}
	// There should only be one match, there should only be one Dxe Core.
	if mlen := len(find.Matches); mlen != 1 {
		return nil, fmt.Errorf("expected exactly one match, got %v, matches were: %v", mlen, find.Matches)
	}
	return find.Matches[0], nil
}

// FindEnclosingFV finds the FV that contains a file.
func FindEnclosingFV(f uefi.Firmware, file *uefi.File) (*uefi.FirmwareVolume, error) {
	pred := func(f uefi.Firmware) bool {
		switch f := f.(type) {
		case *uefi.FirmwareVolume:
			for _, v := range f.Files {
				if v == file {
					return true
				}
			}
		}
		return false
	}
	dxeFV, err := FindExactlyOne(f, pred)
	if err != nil {
		return nil, fmt.Errorf("unable to find DXE FV, got: %v", err)
	}
	// result must be a FV.
	fv, ok := dxeFV.(*uefi.FirmwareVolume)
	if !ok {
		return nil, fmt.Errorf("result was not a firmware volume! was type %T", dxeFV)
	}

	return fv, nil
}

// FindDXEFV is a helper function to quickly retrieve the firmware volume that contains the DxeCore.
func FindDXEFV(f uefi.Firmware) (*uefi.FirmwareVolume, error) {
	// We identify the Dxe Firmware Volume via the presence of the DxeCore
	// This will cause problems if there are multiple dxe volumes.
	pred := FindFileTypePredicate(uefi.FVFileTypeDXECore)
	dxeCore, err := FindExactlyOne(f, pred)
	if err != nil {
		return nil, fmt.Errorf("unable to find DXE Core, got: %v", err)
	}

	// result must be a File.
	file, ok := dxeCore.(*uefi.File)
	if !ok {
		return nil, fmt.Errorf("result was not a file! was type %T", file)
	}
	return FindEnclosingFV(f, file)
}

// FindNVarPredicate is a generic predicate for searching NVar only.
func FindNVarPredicate(r string) (func(f uefi.Firmware) bool, error) {
	searchRE, err := regexp.Compile("^(" + r + ")$")
	if err != nil {
		return nil, err
	}
	return func(f uefi.Firmware) bool {
		switch f := f.(type) {
		case *uefi.NVar:
			return searchRE.MatchString(f.Name)
		}
		return false
	}, nil
}

func init() {
	RegisterCLI("find", "find a file by GUID or Name", 1, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}
		return &Find{
			Predicate: pred,
			W:         os.Stdout,
		}, nil
	})
	RegisterCLI("find_nvar", "find an NVAR by Name", 1, func(args []string) (uefi.Visitor, error) {
		pred, err := FindNVarPredicate(args[0])
		if err != nil {
			return nil, err
		}
		return &Find{
			Predicate: pred,
			W:         os.Stdout,
		}, nil
	})
}
