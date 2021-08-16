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

// Reserved1Offset returns the offset in bytes of field Reserved1
func (h *PSPHeader) Reserved1Offset() uint64 {
	return 0
}

func (h *PSPHeader) Reserved1Length() uint64 {
	return uint64(binary.Size(h.Reserved1))
}

// CookieOffset returns the offset in bytes of field Cookie
func (h *PSPHeader) CookieOffset() uint64 {
	return h.Reserved1Offset() + h.Reserved1Length()
}

// CookieLength returns the size in bytes of field Cookie
func (h *PSPHeader) CookieLength() uint64 {
	return uint64(binary.Size(h.Cookie))
}

// Reserved2Offset returns the offset in bytes of field Reserved2
func (h *PSPHeader) Reserved2Offset() uint64 {
	return h.CookieOffset() + h.CookieLength()
}

// Reserved2Length returns the size in bytes of field Reserved2
func (h *PSPHeader) Reserved2Length() uint64 {
	return uint64(binary.Size(h.Reserved2))
}

// VersionOffset returns the offset in bytes of field Version
func (h *PSPHeader) VersionOffset() uint64 {
	return h.Reserved2Offset() + h.Reserved2Length()
}

// VersionLength returns the size in bytes of field Version
func (h *PSPHeader) VersionLength() uint64 {
	return uint64(binary.Size(h.Version))
}

// ParsePSPHeader parses the PSP header that is supposed to be the beginning of each PSP binary
func ParsePSPHeader(r io.Reader) (*PSPHeader, error) {
	var result PSPHeader
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
