// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Dump a firmware file using a GUID or a name
type Dump struct {
	// Input
	Predicate func(f uefi.Firmware) bool

	// Output
	// The file is written to this writer.
	W io.Writer
}

// Run just calls the visitor
func (v *Dump) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit uses find to dump a file to W.
func (v *Dump) Visit(f uefi.Firmware) error {
	// First run "find" to generate a list to dump
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	// There must only be one match.
	if numMatch := len(find.Matches); numMatch > 1 {
		return fmt.Errorf("more than one match, only one match allowed! got %v", find.Matches)
	} else if numMatch == 0 {
		return errors.New("no matches found")
	}

	m := find.Matches[0]
	// TODO: We may need to call assemble here before dumping as the buffer may be empty
	_, err := v.W.Write(m.Buf())
	return err
}

func init() {
	RegisterCLI("dump", "dump a firmware file", 2, func(args []string) (uefi.Visitor, error) {
		pred, err := FindFilePredicate(args[0])
		if err != nil {
			return nil, err
		}

		file, err := os.OpenFile(args[1], os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return nil, err
		}

		// Find all the matching files and replace their inner PE32s.
		return &Dump{
			Predicate: pred,
			W:         file,
		}, nil
	})
}
