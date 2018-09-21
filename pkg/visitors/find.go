// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Find a firmware file given its name or GUID.
type Find struct {
	// Input
	// Only when this functions returns true will the file appear in the
	// `Matches` slice.
	Predicate func(f *uefi.File, name string) bool

	// Output
	Matches []*uefi.File

	// Private
	currentFile *uefi.File
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Find) Run(f uefi.Firmware) error {
	return f.Apply(v)
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
		err := f.ApplyChildren(v2)
		v.Matches = append(v.Matches, v2.Matches...) // Merge together
		return err

	case *uefi.Section:
		if v.currentFile != nil && v.Predicate(v.currentFile, f.Name) {
			v.Matches = append(v.Matches, v.currentFile)
			v.currentFile = nil // Do not double-match with a sibling.
		}
		return f.ApplyChildren(v)

	default:
		return f.ApplyChildren(v)
	}
}

func init() {
	RegisterCLI("find", "find a file by a GUID regexp", 1, func(args []string) (uefi.Visitor, error) {
		searchRE, err := regexp.Compile(args[0])
		if err != nil {
			return nil, err
		}
		return &Find{
			Predicate: func(f *uefi.File, name string) bool {
				if searchRE.MatchString(name) || searchRE.MatchString(f.Header.GUID.String()) {
					b, err := json.MarshalIndent(f, "", "\t")
					if err != nil {
						log.Fatal(err)
					}
					fmt.Println(string(b))
					return true
				}
				return false
			},
		}, nil
	})
}
