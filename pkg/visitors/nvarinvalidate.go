// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// NVarInvalidate set NVar as Invalid
type NVarInvalidate struct {
	// Input
	Predicate func(f uefi.Firmware) bool

	// Output
	Matches []uefi.Firmware
	// logs are written to this writer.
	W io.Writer
}

func (v *NVarInvalidate) printf(format string, a ...interface{}) {
	if v.W != nil {
		fmt.Fprintf(v.W, format, a...)
	}
}

// Run uses find and wraps Visit.
func (v *NVarInvalidate) Run(f uefi.Firmware) error {
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

// Visit set NVar as Invalid
func (v *NVarInvalidate) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.NVar:
		v.printf("Invalidate: %v  %v\n", f.GUID, f)
		f.Type = uefi.InvalidNVarEntry
	}
	return nil
}

func init() {
	RegisterCLI("invalidate_nvar", "invalidate NVar by Name", 1, func(args []string) (uefi.Visitor, error) {
		pred, err := FindNVarPredicate(args[0])
		if err != nil {
			return nil, err
		}
		return &NVarInvalidate{
			Predicate: pred,
			W:         os.Stdout,
		}, nil
	})
	RegisterCLI("invalidate_nvar_except", "invalidate all NVar except those in the specified file", 1, func(args []string) (uefi.Visitor, error) {
		fileName := args[0]
		fileContents, err := ioutil.ReadFile(fileName)
		if err != nil {
			return nil, fmt.Errorf("cannot read blacklist file %q: %v", fileName, err)
		}
		blackListRegex, err := parseBlackList(fileName, string(fileContents))
		if err != nil {
			return nil, err
		}
		fmt.Printf("JVDG: %v\n", blackListRegex)
		blackListPredicate, err := FindNVarPredicate(blackListRegex)
		if err != nil {
			return nil, err
		}
		pred := FindNotPredicate(blackListPredicate)

		return &NVarInvalidate{
			Predicate: pred,
			W:         os.Stdout,
		}, nil
	})

}
