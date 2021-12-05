// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"encoding/binary"
	"fmt"
	"io"
)

// PSPBootloaderCookie is a special identifier of a PSP binary
const PSPBootloaderCookie = 0x31535024 // "$PS1"

// FirmwareVersion represents PSP firmware version
type FirmwareVersion [4]byte

// String converts FirmwareVersion into a string
func (v FirmwareVersion) String() string {
	return fmt.Sprintf("%x.%x.%x.%x", v[3], v[2], v[1], v[0])
}

// PSPHeader represents a header of each firmware binary
// See: https://doc.coreboot.org/soc/amd/psp_integration.html
type PSPHeader struct {
	Reserved1 [16]byte
	Cookie    uint32
	Reserved2 [76]byte
	Version   FirmwareVersion
	Reserved3 [156]byte
}

// ParsePSPHeader parses
func ParsePSPHeader(r io.Reader) (*PSPHeader, error) {
	var result PSPHeader
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
