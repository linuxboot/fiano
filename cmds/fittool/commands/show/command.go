// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package show

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/linuxboot/fiano/cmds/fittool/commands"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

var _ commands.Command = (*Command)(nil)

type Command struct {
	UEFIPath    string  `short:"f" long:"uefi" description:"path to UEFI image" required:"true"`
	Format      *string `long:"format" description:"output format [text, json]"`
	IncludeData *bool   `long:"include-data" description:"print also data section referenced by the FIT headers"`
}

type Format int

const (
	FormatUndefined = Format(iota)
	FormatText
	FormatJSON
)

func ParseFormat(s string) Format {
	switch strings.Trim(strings.ToLower(s), " ") {
	case "text":
		return FormatText
	case "json":
		return FormatJSON
	}
	return FormatUndefined
}

// ShortDescription explains what this command does in one line
func (cmd *Command) ShortDescription() string {
	return "prints FIT"
}

// LongDescription explains what this verb does (without limitation in amount of lines)
func (cmd *Command) LongDescription() string {
	return ""
}

// Execute is the main function here. It is responsible to
// start the execution of the command.
//
// `args` are the arguments left unused by verb itself and options.
func (cmd *Command) Execute(args []string) error {
	if len(args) != 0 {
		return commands.ErrArgs{Err: fmt.Errorf("there are extra arguments")}
	}

	includeData := false
	if cmd.IncludeData != nil {
		includeData = *cmd.IncludeData
	}

	format := FormatText
	if cmd.Format != nil {
		format = ParseFormat(*cmd.Format)
		if format == FormatUndefined {
			return commands.ErrArgs{Err: fmt.Errorf("unknown format '%s'", *cmd.Format)}
		}
	}

	file, err := os.OpenFile(cmd.UEFIPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unable to open the firmware image file '%s': %w", cmd.UEFIPath, err)
	}

	entries, err := fit.GetEntriesFrom(file)
	if err != nil {
		return fmt.Errorf("unable to get FIT entries: %w", err)
	}

	switch format {
	case FormatText:
		if includeData {
			fmt.Printf("%s", entries.String())
		} else {
			fmt.Printf("%s", entries.Table().String())
		}
	case FormatJSON:
		var b []byte
		var err error
		if includeData {
			b, err = json.Marshal(entries)
		} else {
			b, err = json.Marshal(entries.Table())
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", b)
	}

	return nil
}
