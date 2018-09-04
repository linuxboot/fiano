// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"io/ioutil"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Save calls Assemble, then outputs the top image to a file.
type Save struct {
	DirPath string
}

// Run just applies the visitor.
func (v *Save) Run(f uefi.Firmware) error {
	return f.Apply(v)
}

// Visit calls the assemble visitor to make sure everything is reconstructed.
// It then outputs the top level buffer to a file.
func (v *Save) Visit(f uefi.Firmware) error {
	a := &Assemble{}
	// Assemble the binary to make sure the top level buffer is correct
	if err := f.Apply(a); err != nil {
		return err
	}
	return ioutil.WriteFile(v.DirPath, f.Buf(), 0666)
}

func init() {
	RegisterCLI("save", 1, func(args []string) (uefi.Visitor, error) {
		return &Save{
			DirPath: args[0],
		}, nil
	})
}
