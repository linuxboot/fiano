// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/linuxboot/fiano/uefi"
)

// ParseDir creates the firmware tree and reads the binaries from the provided directory
type ParseDir struct {
	DirPath string
}

// Run is not actually implemented cause we can't fit the interface
func (v *ParseDir) Run(f uefi.Firmware) error {
	return errors.New("func Run for ParseDir is not implemented, do not use")
}

// Parse parses a directory and creates the tree.
func (v *ParseDir) Parse() (uefi.Firmware, error) {
	// Change working directory so we can use relative paths.
	// TODO: commands after this in the pipeline are in unexpected directory
	if err := os.Chdir(v.DirPath); err != nil {
		return nil, err
	}

	jsonbuf, err := ioutil.ReadFile("summary.json")
	if err != nil {
		return nil, err
	}
	f, err := uefi.UnmarshalFirmware(jsonbuf)
	if err != nil {
		return nil, err
	}

	if err = f.Apply(&ParseDir{DirPath: "."}); err != nil {
		return nil, err
	}
	return f, nil
}

func readBuf(ExtractPath string) ([]byte, error) {
	if ExtractPath != "" {
		return ioutil.ReadFile(ExtractPath)
	}
	return nil, nil
}

// Visit applies the ParseDir visitor to any Firmware type.
func (v *ParseDir) Visit(f uefi.Firmware) error {
	var err error
	switch f := f.(type) {

	case *uefi.FirmwareVolume:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.File:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.Section:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.FlashDescriptor:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.BIOSRegion:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.GBERegion:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.MERegion:
		f.Buf, err = readBuf(f.ExtractPath)

	case *uefi.PDRegion:
		f.Buf, err = readBuf(f.ExtractPath)
	}

	if err != nil {
		return err
	}

	return f.ApplyChildren(v)
}
