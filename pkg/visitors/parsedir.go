// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// ParseDir creates the firmware tree and reads the binaries from the provided directory
type ParseDir struct {
	BasePath string
}

// Run is not actually implemented cause we can't fit the interface
func (v *ParseDir) Run(f uefi.Firmware) error {
	return errors.New("func Run for ParseDir is not implemented, do not use")
}

// Parse parses a directory and creates the tree.
func (v *ParseDir) Parse() (uefi.Firmware, error) {
	// Read in the json and construct the tree.
	jsonbuf, err := os.ReadFile(filepath.Join(v.BasePath, "summary.json"))
	if err != nil {
		return nil, err
	}
	f, err := uefi.UnmarshalFirmware(jsonbuf)
	if err != nil {
		return nil, err
	}

	if err = f.Apply(v); err != nil {
		return nil, err
	}
	return f, nil
}

func (v *ParseDir) readBuf(ExtractPath string) ([]byte, error) {
	if ExtractPath != "" {
		return os.ReadFile(filepath.Join(v.BasePath, ExtractPath))
	}
	return nil, nil
}

// Visit applies the ParseDir visitor to any Firmware type.
func (v *ParseDir) Visit(f uefi.Firmware) error {
	var err error
	var fBuf []byte
	switch f := f.(type) {

	case *uefi.FirmwareVolume:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.File:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.Section:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.NVar:
		if f.IsValid() {
			var fValBuf []byte
			fValBuf, err = v.readBuf(f.ExtractPath)
			fBuf = append(make([]byte, f.DataOffset), fValBuf...)
		} else {
			fBuf, err = v.readBuf(f.ExtractPath)
		}

	case *uefi.FlashDescriptor:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.BIOSRegion:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.MERegion:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.RawRegion:
		fBuf, err = v.readBuf(f.ExtractPath)

	case *uefi.BIOSPadding:
		fBuf, err = v.readBuf(f.ExtractPath)
	}

	if err != nil {
		return err
	}
	f.SetBuf(fBuf)

	return f.ApplyChildren(v)
}
