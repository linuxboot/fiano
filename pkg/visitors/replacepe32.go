// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"errors"
	"io/ioutil"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// ReplacePE32 replaces PE32 sections with NewPE32 for all files matching Predicate.
type ReplacePE32 struct {
	// Input
	Predicate func(f uefi.Firmware) bool
	NewPE32   []byte

	// Output
	Matches []uefi.Firmware
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *ReplacePE32) Run(f uefi.Firmware) error {
	// Check that we're actually replacing with a PE32 image
	if !bytes.HasPrefix(v.NewPE32, []byte("MZ")) {
		return errors.New("supplied binary is not a valid pe32 image")
	}

	// Run "find" to generate a list of matches to replace.
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	// Use this list of matches for replacing sections.
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

// Visit applies the Extract visitor to any Firmware type.
func (v *ReplacePE32) Visit(f uefi.Firmware) error {
	switch f := f.(type) {

	case *uefi.File:
		return f.ApplyChildren(v)

	case *uefi.Section:
		if f.Header.Type == uefi.SectionTypePE32 {
			f.SetBuf(v.NewPE32)
			f.Encapsulated = nil // Should already be empty
			f.GenSecHeader()
		}
		return f.ApplyChildren(v)

	default:
		// Must be applied to a File to have any effect.
		return nil
	}
}

func init() {
	RegisterCLI("replace_pe32", "replace a pe32 given a GUID and new file", 2, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}

		filename := args[1]
		newPE32, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		// Find all the matching files and replace their inner PE32s.
		return &ReplacePE32{
			Predicate: pred,
			NewPE32:   newPE32,
		}, nil
	})
}
