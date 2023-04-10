// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode"
)

var Debug = func(format string, v ...interface{}) {}

// Read reads things in in BE format, which they are supposed to be in.
func Read(r io.Reader, f interface{}) error {
	// NOTE: THIS is the `Read` you are looking for!
	if err := binary.Read(r, Endian, f); err != nil {
		if err == io.EOF {
			Debug("Read %v: reached EOF", f)
		}
		return err
	}
	return nil
}

// ReadLE reads things in LE format, which the spec says it is not in.
func ReadLE(r io.Reader, f interface{}) error {
	if err := binary.Read(r, binary.LittleEndian, f); err != nil {
		return err
	}
	return nil
}

// Write reads things in in BE format, which they are supposed to be in.
func Write(w io.Writer, f interface{}) error {
	if err := binary.Write(w, Endian, f); err != nil {
		return err
	}
	return nil
}

// WriteLE reads things in LE format, which the spec says it is not in.
func WriteLE(r io.Writer, f interface{}) error {
	if err := binary.Write(r, binary.LittleEndian, f); err != nil {
		return err
	}
	return nil
}

func (c Compression) String() string {
	switch c {
	case None:
		return "none"
	case LZMA:
		return "lzma"
	case LZ4:
		return "lz4"
	}
	return "unknown"
}

func (f FileType) String() string {
	switch f {
	case TypeDeleted2:
		return "Deleted2"
	case TypeDeleted:
		return "Deleted"
	case TypeMaster:
		return "cbfs header"
	case TypeBootBlock:
		return "BootBlock"
	case TypeLegacyStage:
		return "LegacyStage"
	case TypeStage:
		return "Stage"
	case TypeSELF:
		return "SELF"
	case TypeFIT:
		return "FIT"
	case TypeOptionRom:
		return "OptionRom"
	case TypeBootSplash:
		return "BootSplash"
	case TypeRaw:
		return "Raw"
	case TypeVSA:
		return "VSA"
	case TypeMBI:
		return "MBI"
	case TypeMicroCode:
		return "MicroCode"
	case TypeFSP:
		return "FSP"
	case TypeMRC:
		return "MRC"
	case TypeMMA:
		return "MMA"
	case TypeEFI:
		return "EFI"
	case TypeStruct:
		return "Struct"
	case TypeCMOS:
		return "CMOS"
	case TypeSPD:
		return "SPD"
	case TypeMRCCache:
		return "MRCCache"
	case TypeCMOSLayout:
		return "CMOSLayout"
	}
	return fmt.Sprintf("%#x", uint32(f))
}

func recString(n string, off uint32, typ string, sz uint32, compress string) string {
	return fmt.Sprintf("%-32s 0x%-8x %-24s 0x%-8x %-4s", n, off, typ, sz, compress)
}

// Clean up non-printable and other characters. 0xfffd is the Unicode tofu char,
// aka 'REPLACEMENT CHARACTER': https://unicodemap.org/details/0xFFFD/index.html
// Would occur e.g. from `0x66616c6c6261636b2f726f6d737461676500...00ff...ff`.
func cleanString(n string) string {
	return strings.Map(func(r rune) rune {
		if r != 0xfffd && (unicode.IsPrint(r) || unicode.IsGraphic(r)) {
			return r
		}
		return -1
	}, n)
}

func ffbyte(s uint32) []byte {
	b := make([]byte, s)
	for i := range b {
		b[i] = 0xff
	}
	return b
}
