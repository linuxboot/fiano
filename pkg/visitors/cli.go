// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package visitors uses the Visitor interface to recursively apply an
// operation over the firmware image. Also, functions are exported for using
// the visitors through the command line.
package visitors

import (
	"fmt"
	"sort"

	"github.com/linuxboot/fiano/pkg/uefi"
)

var visitorRegistry = map[string]visitorEntry{}

type visitorEntry struct {
	numArgs       int
	help          string
	createVisitor func([]string) (uefi.Visitor, error)
}

const (
	helpMessage = "Usage: utk FILE [COMMAND [ARGS]]..."
)

// RegisterCLI registers a function `createVisitor` to be called when parsing
// the arguments with `ParseCLI`. For a Visitor to be accessible from the
// command line, it should have an init function which registers a
// `createVisitor` function here.
func RegisterCLI(name string, help string, numArgs int, createVisitor func([]string) (uefi.Visitor, error)) {
	if _, ok := visitorRegistry[name]; ok {
		panic(fmt.Sprintf("two visitors registered the same name: '%s'", name))
	}
	visitorRegistry[name] = visitorEntry{
		numArgs:       numArgs,
		createVisitor: createVisitor,
		help:          help,
	}
}

// ParseCLI constructs a list of visitors from the given CLI argument list.
func ParseCLI(args []string) ([]uefi.Visitor, error) {
	visitors := []uefi.Visitor{}
	for len(args) > 0 {
		cmd := args[0]
		args = args[1:]
		o, ok := visitorRegistry[cmd]
		if !ok {
			return []uefi.Visitor{}, fmt.Errorf("could not find command '%s'\n%s", cmd, helpMessage)
		}
		if o.numArgs > len(args) {
			return []uefi.Visitor{}, fmt.Errorf("too few arguments for command '%s', got %d, expected %d.\nSynopsis: %s",
				cmd, len(args), o.numArgs, o.help)
		}
		visitor, err := o.createVisitor(args[:o.numArgs])
		if err != nil {
			return []uefi.Visitor{}, err
		}
		visitors = append(visitors, visitor)
		args = args[o.numArgs:]
	}
	return visitors, nil
}

// ExecuteCLI applies each Visitor over the firmware in sequence.
func ExecuteCLI(f uefi.Firmware, v []uefi.Visitor) error {
	for i := range v {
		if err := v[i].Run(f); err != nil {
			return err
		}
	}
	return nil
}

// ListCLI prints out the help entries in the visitor struct
// as a newline-separated string in the form:
//
//	name: help
func ListCLI() string {
	var s string
	names := []string{}
	for n := range visitorRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s += fmt.Sprintf("  %-22s: %s\n", n, visitorRegistry[n].help)
	}
	return s
}
