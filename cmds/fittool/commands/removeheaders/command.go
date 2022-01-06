// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package removeheaders

import (
	"fmt"
	"os"

	"github.com/linuxboot/fiano/cmds/fittool/commands"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

var _ commands.Command = (*Command)(nil)

type Command struct {
	UEFIPath    string `description:"path to UEFI image" required:"true" short:"f" long:"uefi"`
	EntryNumber uint   `description:"FIT entry number" required:"true" short:"n" long:"entry-number"`
}

// ShortDescription explains what this command does in one line
func (cmd *Command) ShortDescription() string {
	return "remove a headers entry from FIT (but does not remove referenced data)"
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

	table, err := fit.GetTableFrom(file)
	if err != nil {
		return fmt.Errorf("unable to get FIT from the firmware image: %w", err)
	}

	if len(table) == 0 {
		return fmt.Errorf("FIT is not initialized in the image")
	}

	if len(table) <= int(cmd.EntryNumber) {
		return fmt.Errorf("there are only %d entries in the FIT (no entry # %d)", len(table), cmd.EntryNumber)
	}

	for idx := int(cmd.EntryNumber); idx < len(table)-1; idx++ {
		table[idx] = table[idx+1]
	}
	lastEntry := &table[len(table)-1]
	*lastEntry = fit.EntryHeaders{} // fill with zeros

	table[0].Size.SetUint32(uint32(len(table)) - 1)
	if _, err := table.WriteToFirmwareImage(file); err != nil {
		return fmt.Errorf("unable to write FIT into a firmware: %w", err)
	}
	return nil
}
