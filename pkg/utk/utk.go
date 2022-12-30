// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package utk is where the implementation of the utk command lives.
package utk

import (
	"errors"
	"os"

	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/visitors"
)

// Run runs the utk command with the given arguments.
func Run(args ...string) error {
	if len(args) == 0 {
		return errors.New("at least one argument is required")
	}

	v, err := visitors.ParseCLI(args[1:])
	if err != nil {
		return err
	}

	// Load and parse the image.
	path := args[0]
	f, err := os.Stat(path)
	if err != nil {
		return err
	}
	var parsedRoot uefi.Firmware
	if m := f.Mode(); m.IsDir() {
		// Call ParseDir
		pd := visitors.ParseDir{BasePath: path}
		if parsedRoot, err = pd.Parse(); err != nil {
			return err
		}
		// Assemble the tree from the bottom up
		a := visitors.Assemble{}
		if err = a.Run(parsedRoot); err != nil {
			return err
		}
	} else {
		// Regular file
		image, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsedRoot, err = uefi.Parse(image)
		if err != nil {
			return err
		}
	}

	// Execute the instructions from the command line.
	return visitors.ExecuteCLI(parsedRoot, v)
}
