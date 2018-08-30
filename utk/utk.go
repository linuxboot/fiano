// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/subcommands"
	"github.com/linuxboot/fiano/uefi"
	"github.com/linuxboot/fiano/visitors"
)

// Parse subcommand
type parseCmd struct {
	warn bool
}

func (*parseCmd) Name() string {
	return "parse"
}

func (*parseCmd) Synopsis() string {
	return "Parse rom file and print JSON summary to stdout"
}

func (*parseCmd) Usage() string {
	return "parse <path-to-rom-file>\n"
}

func (p *parseCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.warn, "warn", false, "warn instead of fail on validation errors")
}

func (p *parseCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	args := f.Args()
	if len(args) == 0 {
		log.Print("A file name is required")
		return subcommands.ExitUsageError
	}

	romfile := args[0]
	buf, err := ioutil.ReadFile(romfile)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	firmware, err := uefi.Parse(buf)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	errlist := firmware.Validate()
	for _, err := range errlist {
		log.Printf("Error found: %v\n", err.Error())
	}
	errlen := len(errlist)
	if !p.warn && errlen > 0 {
		return subcommands.ExitFailure
	}

	b, err := uefi.MarshalFirmware(firmware)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	fmt.Println(string(b))
	if errlen > 0 {
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

// Extract subcommand
type extractCmd struct {
	force  bool
	warn   bool
	remove bool
}

func (*extractCmd) Name() string {
	return "extract"
}

func (*extractCmd) Synopsis() string {
	return "Extract rom file and print JSON summary to stdout"
}

func (*extractCmd) Usage() string {
	return "extract <path-to-rom-file> <directory-to-extract-into>\n"
}

func (e *extractCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&e.force, "force", false, "force extract to non empty directory")
	f.BoolVar(&e.warn, "warn", false, "warn instead of fail on validation errors")
	f.BoolVar(&e.remove, "remove", false, "remove existing directory before extracting")
}

func (e *extractCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	args := f.Args()
	if len(args) < 2 {
		log.Print(e.Usage())
		return subcommands.ExitUsageError
	}

	romfile := args[0]
	buf, err := ioutil.ReadFile(romfile)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	firmware, err := uefi.Parse(buf)
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}
	errlist := firmware.Validate()
	for _, err := range errlist {
		log.Printf("Error found: %v\n", err.Error())
	}
	errlen := len(errlist)
	if !e.warn && errlen > 0 {
		return subcommands.ExitFailure
	}

	if e.remove {
		if err := os.RemoveAll(args[1]); err != nil {
			log.Printf("Error removing path %v, got %v\n", args[1], err)
		}
	}
	if !e.force {
		// check that directory doesn't exist or is empty
		files, err := ioutil.ReadDir(args[1])
		if err == nil {
			if len(files) != 0 {
				log.Print("Existing directory not empty, use --force to override")
				return subcommands.ExitFailure
			}
		} else if !os.IsNotExist(err) {
			// error was not EEXIST, we don't know what went wrong.
			log.Print(err)
			return subcommands.ExitFailure
		}
	}

	// Extract all elements.
	if err := (&visitors.Extract{DirPath: args[1]}).Run(firmware); err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	if errlen > 0 {
		// Return failure even if warn is set.
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

// Assemble subcommand
type assembleCmd struct {
}

func (*assembleCmd) Name() string {
	return "assemble"
}

func (*assembleCmd) Synopsis() string {
	return "Assemble rom file from directory tree."
}

func (*assembleCmd) Usage() string {
	return "assemble <directory-to-assemble-from> <newromfile>\n"
}

func (*assembleCmd) SetFlags(_ *flag.FlagSet) {}

func (a *assembleCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	args := f.Args()
	if len(args) < 2 {
		log.Print(a.Usage())
		return subcommands.ExitUsageError
	}

	// Parse.
	firmware, err := (&visitors.ParseDir{DirPath: args[0]}).Parse()
	if err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	// Save.
	if err := (&visitors.Save{DirPath: args[1]}).Run(firmware); err != nil {
		log.Print(err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&parseCmd{}, "")
	subcommands.Register(&extractCmd{}, "")
	subcommands.Register(&assembleCmd{}, "")
	flag.Parse()

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
