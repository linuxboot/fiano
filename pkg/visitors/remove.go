// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Remove all firmware files with the given GUID.
type Remove struct {
	// Input
	Predicate  func(f uefi.Firmware) bool
	Pad        bool
	RemoveDxes bool // I hate this, but there's no good way to work around our current structure

	// Output
	Matches []uefi.Firmware
	// Calling this function undoes the removals performed by this visitor.
	Undo func()
	// logs are written to this writer.
	W io.Writer
}

func (v *Remove) printf(format string, a ...interface{}) {
	if v.W != nil {
		fmt.Fprintf(v.W, format, a...)
	}
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Remove) Run(f uefi.Firmware) error {
	// First run "find" to generate a list of matches to delete.
	find := Find{
		Predicate: v.Predicate,
	}
	if v.RemoveDxes {
		dxeFV, err := FindDXEFV(f)
		if err != nil {
			return err
		}
		if err := find.Run(dxeFV); err != nil {
			return err
		}
		// We've found all the files in the blacklist
		// now, we invert the matches
		// Note, we can't use the NotPredicate here because that will match the
		// sections of all files even if they are supposed to be excluded.
		// This is terrible and my fault.
		newMatches := []uefi.Firmware{}
		for _, file := range dxeFV.Files {
			var keep bool
			for _, match := range find.Matches {
				if match == file {
					keep = true
					break
				}
			}
			if !keep {
				newMatches = append(newMatches, file)
			}
		}

		// Use this list of matches when removing files.
		v.Matches = newMatches
		return dxeFV.Apply(v)
	}
	if err := find.Run(f); err != nil {
		return err
	}

	// Use this list of matches when removing files.
	v.Matches = find.Matches
	return f.Apply(v)
}

// Visit applies the Remove visitor to any Firmware type.
func (v *Remove) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FirmwareVolume:
		for i := 0; i < len(f.Files); i++ {
			for _, m := range v.Matches {
				if f.Files[i] == m {
					originalList := append([]*uefi.File{}, f.Files...)

					m := m.(*uefi.File)
					if v.Pad || m.Header.Type == uefi.FVFileTypePEIM {
						// Create a new pad file of the exact same size
						pf, err := uefi.CreatePadFile(m.Header.ExtendedSize)
						if err != nil {
							return err
						}
						f.Files[i] = pf
					} else {
						f.Files = append(f.Files[:i], f.Files[i+1:]...)
					}
					v.printf("Remove: %d files now", len(f.Files))

					// Creates a stack of undoes in case there are multiple FVs.
					prev := v.Undo
					v.Undo = func() {
						f.Files = originalList
						v.printf("Undo: %d files now", len(f.Files))
						v.Undo = prev
					}
				}
			}
		}
	}

	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("remove", "remove a file from the volume", 1, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}
		return &Remove{
			Predicate: pred,
			Pad:       false,
			W:         Stdout,
		}, nil
	})
	RegisterCLI("remove_pad", "remove a file from the volume and replace it with a pad file of the same size", 1, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}
		return &Remove{
			Predicate: pred,
			Pad:       true,
			W:         Stdout,
		}, nil
	})
	RegisterCLI("remove_dxes_except", "remove all files from the volume except those in the specified file", 1, func(args []string) (uefi.Visitor, error) {
		fileName := args[0]
		fileContents, err := ioutil.ReadFile(fileName)
		if err != nil {
			return nil, fmt.Errorf("cannot read blacklist file %q: %v", fileName, err)
		}
		blackListRegex, err := parseBlackList(fileName, string(fileContents))
		if err != nil {
			return nil, err
		}
		blackListPredicate, err := FindFilePredicate(blackListRegex)
		if err != nil {
			return nil, err
		}
		pred := blackListPredicate

		return &Remove{
			Predicate:  pred,
			RemoveDxes: true,
		}, nil
	})
}
