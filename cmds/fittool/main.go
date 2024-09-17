// Copyright 2017-2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// fittool manipulates Intel Firmware Interface Table (FIT) in an UEFI image.
//
//
// See "Firmware Interface Table BIOS Specification":
// * https://www.intel.com/content/dam/develop/external/us/en/documents/firmware-interface-table-bios-specification-r1p2p1.pdf
//
// Synopsis:
//     fittool init -f UEFI_FILE
//     fittool add_raw_headers -f UEFI_FILE [options]
//     fittool set_raw_headers -f UEFI_FILE -n ENTRY_ID [options]
//     fittool remove_headers -f UEFI_FILE -n ENTRY_ID [options]
//     fittool show -f UEFI_FILE [options]
//
// An example:
//     fittool init -f firmware.fd
//     fittool add_raw_headers -f firmware.fd --type 2 --address $((16#100000)) --size $((16#20000))
//     fittool set_raw_headers -f firmware.fd -n 1 --type $((16#7F))
//     fittool remove_headers -f firmware.fd -n 1
//     fittool show -f firmware.fd --format=json --include-data | jq -r '.[] | select(.Headers.Type == 2) | .DataParsed.EntrySACMDataInterface.TXTSVN'
//
// Description:
//     init:            Creates a FIT
//     add_raw_headers: Add raw headers to FIT
//     set_raw_headers: Overwrite the row # ENTRY_ID with specified RAW headers
//     remove_headers:  Remove headers from row entry # ENTRY_ID
//     show:            Print FIT
//
// For more advanced key manifest and boot policy manifest management see also Converged Security Suite:
// * https://github.com/9elements/converged-security-suite
/**
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
 */
package main

import (
	"log"

	"github.com/jessevdk/go-flags"

	"github.com/linuxboot/fiano/cmds/fittool/commands"
	"github.com/linuxboot/fiano/cmds/fittool/commands/addrawheaders"
	_init "github.com/linuxboot/fiano/cmds/fittool/commands/init"
	"github.com/linuxboot/fiano/cmds/fittool/commands/removeheaders"
	"github.com/linuxboot/fiano/cmds/fittool/commands/setrawheaders"
	"github.com/linuxboot/fiano/cmds/fittool/commands/show"
)

var (
	knownCommands = map[string]commands.Command{
		"init":            &_init.Command{},
		"show":            &show.Command{},
		"add_raw_headers": &addrawheaders.Command{},
		"set_raw_headers": &setrawheaders.Command{},
		"remove_headers":  &removeheaders.Command{},
	}
)

func main() {
	flagsParser := flags.NewParser(nil, flags.Default)
	for commandName, command := range knownCommands {
		_, err := flagsParser.AddCommand(commandName, command.ShortDescription(), command.LongDescription(), command)
		if err != nil {
			panic(err)
		}
	}

	// parse arguments and execute the appropriate command
	if _, err := flagsParser.Parse(); err != nil {
		log.Fatal(err)
	}
}
