// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package addrawheaders

import (
	"fmt"
	"io"
	"os"

	"github.com/linuxboot/fiano/cmds/fittool/commands"
	"github.com/linuxboot/fiano/pkg/intel/metadata/fit"
)

var _ commands.Command = (*Command)(nil)

type Command struct {
	UEFIPath        string  `description:"path to UEFI image" required:"true" short:"f" long:"uefi"`
	AddressPointer  *uint64 `description:"the value for field 'ADDRESS'" long:"address-pointer"`
	AddressOffset   *uint64 `description:"the offset value to calculate the value for field 'ADDRESS'" long:"address-offset"`
	Size            *uint32 `description:"the value for field 'SIZE'" long:"size"`
	Version         *uint16 `description:"the value for field 'VERSION'" long:"version"`
	Type            *uint8  `description:"the value for field 'TYPE'" long:"type"`
	IsChecksumValid *bool   `description:"the value for field 'C_V'" long:"is-checksum-valid"`
	Checksum        *uint8  `description:"the value for field 'CHECKSUM'" long:"checksum"`
}

// ShortDescription explains what this command does in one line
func (cmd *Command) ShortDescription() string {
	return "insert an additional FIT entry headers to the UEFI image"
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

	if cmd.AddressOffset != nil && cmd.AddressPointer != nil {
		return commands.ErrArgs{Err: fmt.Errorf("it does not make sense to use '--address-pointer' and '--address-offset' together")}
	}

	if cmd.Type != nil && *cmd.Type >= 0x80 {
		return commands.ErrArgs{Err: fmt.Errorf("invalid value of 'type', it should be less than 0x80")}
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

	entryHeaders := &fit.EntryHeaders{
		Version: fit.EntryVersion(0x1000),
	}
	entryHeaders.TypeAndIsChecksumValid.SetType(fit.EntryTypeSkip)

	if cmd.AddressPointer != nil {
		entryHeaders.Address = fit.Address64(*cmd.AddressPointer)
	}
	if cmd.AddressOffset != nil {
		fileSize, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			return fmt.Errorf("unable to determine the file size: %w", err)
		}
		entryHeaders.Address.SetOffset(*cmd.AddressOffset, uint64(fileSize))
	}
	if cmd.Size != nil {
		entryHeaders.Size.SetUint32(*cmd.Size)
	}
	if cmd.IsChecksumValid != nil {
		entryHeaders.TypeAndIsChecksumValid.SetIsChecksumValid(*cmd.IsChecksumValid)
	}
	if cmd.Type != nil {
		entryHeaders.TypeAndIsChecksumValid.SetType(fit.EntryType(*cmd.Type))
	}
	if entryHeaders.TypeAndIsChecksumValid.IsChecksumValid() {
		entryHeaders.Checksum = entryHeaders.CalculateChecksum()
	}

	if cmd.Checksum != nil {
		entryHeaders.Checksum = *cmd.Checksum
	}

	if table[0].Type() != fit.EntryTypeFITHeaderEntry {
		return fmt.Errorf("the first entry should be of type 0x00")
	}
	table = append(table, *entryHeaders)
	table[0].Size.SetUint32(uint32(len(table)))
	if _, err := table.WriteToFirmwareImage(file); err != nil {
		return fmt.Errorf("unable to write FIT into a firmware: %w", err)
	}
	return nil
}
