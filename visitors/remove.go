// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"regexp"

	"github.com/linuxboot/fiano/uefi"
)

// Remove all firmware files with the given GUID.
type Remove struct {
	// Input
	Predicate func(f *uefi.File, name string) bool

	// Output
	Matches []*uefi.File
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
					f.Files = append(f.Files[:i], f.Files[i+1:]...)
				}
			}
		}
	}

	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("remove", 1, func(args []string) (uefi.Visitor, error) {
		searchRE, err := regexp.Compile(args[0])
		if err != nil {
			return nil, err
		}
		return &Remove{
			Predicate: func(f *uefi.File, name string) bool {
				return searchRE.MatchString(name) || searchRE.MatchString(f.Header.UUID.String())
			},
		}, nil
	})
}
