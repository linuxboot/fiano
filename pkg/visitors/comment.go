// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// Comment holds the io.Writer and args for a comment
type Comment struct {
	W io.Writer
	s string
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Comment) Run(f uefi.Firmware) error {
	fmt.Fprintf(v.W, "%s\n", v.s)
	return nil
}

// Visit applies the Comment visitor to any Firmware type.
func (v *Comment) Visit(f uefi.Firmware) error {
	return nil
}

func init() {
	RegisterCLI("comment", "Print one arg", 1, func(args []string) (uefi.Visitor, error) {
		return &Comment{W: Stdout, s: args[0]}, nil
	})
}
