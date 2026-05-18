// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// ReplaceRaw replaces EFI_SECTION_RAW sections with NewRaw for all files matching Predicate.
type ReplaceRaw struct {
	// Input
	Predicate func(f uefi.Firmware) bool
	NewRaw    []byte

	// Output
	Matches []uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *ReplaceRaw) Run(f uefi.Firmware) error {
	// Run "find" to generate a list of matches to replace.
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	v.Matches = find.Matches
	if len(find.Matches) == 0 {
		return errors.New("no matches found for replacement")
	}
	if len(find.Matches) > 1 {
		return errors.New("multiple matches found! There can be only one. Use find to list all matches")
	}

	for _, m := range v.Matches {
		if err := m.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

// Visit applies the ReplaceRaw visitor to any Firmware type.
func (v *ReplaceRaw) Visit(f uefi.Firmware) error {
	switch f := f.(type) {

	case *uefi.File:
		return f.ApplyChildren(v)

	case *uefi.Section:
		if f.Header.Type == uefi.SectionTypeRaw {
			f.SetBuf(v.NewRaw)
			f.Encapsulated = nil // Raw sections have no encapsulated children
			if err := f.GenSecHeader(); err != nil {
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
	RegisterCLI("replace_raw", "replace a raw section given a GUID or name and new file", 2, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}

		filename := args[1]
		newRaw, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		return &ReplaceRaw{
			Predicate: pred,
			NewRaw:    newRaw,
		}, nil
	})
}
