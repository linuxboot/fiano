// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package init

import (
	"fmt"
	"io"
	"os"

	"github.com/linuxboot/fiano/cmds/fittool/commands"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit/consts"
)

var _ commands.Command = (*Command)(nil)

type Command struct {
	UEFIPath string `short:"f" long:"uefi" description:"path to UEFI image" required:"true"`
	Pointer  uint64 `short:"p" long:"pointer" description:"the FIT pointer value" required:"true"`
}

// ShortDescription explains what this command does in one line
func (cmd *Command) ShortDescription() string {
	return "initializes FIT: insert a FIT pointer and the FIT entry of type 0x00"
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

	file, err := os.OpenFile(cmd.UEFIPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unable to open the firmware image file '%s': %w", cmd.UEFIPath, err)
	}

	fileSize, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("unable to detect file size (through seek): %w", err)
	}

	entries := fit.Entries{
		&fit.EntryFITHeaderEntry{},
	}
	if err := entries.RecalculateHeaders(); err != nil {
		return fmt.Errorf("unable to recalculate headers: %w", err)
	}

	if err := entries.InjectTo(file, fit.CalculateOffsetFromPhysAddr(consts.BasePhysAddr-cmd.Pointer, uint64(fileSize))); err != nil {
		return fmt.Errorf("unable to inject entries to the firmware: %w", err)
	}

	return nil
}
