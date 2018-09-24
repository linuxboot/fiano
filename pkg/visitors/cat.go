// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"io"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Cat concatenates all RAW data sections from a file into a single byte slice.
type Cat struct {
	// Input
	Predicate func(f uefi.Firmware) bool

	// Output
	io.Writer
	Matches []uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Cat) Run(f uefi.Firmware) error {
	// First run "find" to generate a list of matches to replace.
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	v.Matches = find.Matches
	for _, m := range v.Matches {
		if err := m.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

// Visit applies the Extract visitor to any Firmware type.
func (v *Cat) Visit(f uefi.Firmware) error {
	switch f := f.(type) {

	case *uefi.File:
		return f.ApplyChildren(v)

	case *uefi.Section:
		if f.Header.Type == uefi.SectionTypeRaw {
			// TODO: figure out how to compute how many bytes
			// to throw away. We tried once and gave up.
			// UEFI ... what can you say.
			if _, err := v.Write(f.Buf()[4:]); err != nil {
				return err
			}
		}
		return f.ApplyChildren(v)

	default:
		// Must be applied to a File to have any effect.
		return nil
	}
}

func init() {
	RegisterCLI("cat", "cat a file with a regexp that matches a GUID", 1, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}
		return &Cat{
			Predicate: pred,
			Writer:    os.Stdout,
		}, nil
	})
}
