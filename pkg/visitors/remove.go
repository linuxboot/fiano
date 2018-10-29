// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"github.com/linuxboot/fiano/pkg/uefi"
)

// Remove all firmware files with the given GUID.
type Remove struct {
	// Input
	Predicate func(f uefi.Firmware) bool
	Pad       bool

	// Output
	Matches []uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Remove) Run(f uefi.Firmware) error {
	// First run "find" to generate a list of matches to delete.
	find := Find{
		Predicate: v.Predicate,
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
		}, nil
	})
}
