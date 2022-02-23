// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode"
)

var Debug = func(format string, v ...interface{}) {}

// Read reads things in in BE format, which they are supposed to be in.
func Read(r io.Reader, f interface{}) error {
	if err := binary.Read(r, Endian, f); err != nil {
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
		return "TypeDeleted2"
	case TypeDeleted:
		return "TypeDeleted"
	case TypeMaster:
		return "cbfs header"
	case TypeBootBlock:
		return "TypeBootBlock"
	case TypeLegacyStage:
		return "TypeLegacyStage"
	case TypeStage:
		return "TypeStage"
	case TypeSELF:
		return "TypeSELF"
	case TypeFIT:
		return "TypeFIT"
	case TypeOptionRom:
		return "TypeOptionRom"
	case TypeBootSplash:
		return "TypeBootSplash"
	case TypeRaw:
		return "TypeRaw"
	case TypeVSA:
		return "TypeVSA"
	case TypeMBI:
		return "TypeMBI"
	case TypeMicroCode:
		return "TypeMicroCode"
	case TypeFSP:
		return "TypeFSP"
	case TypeMRC:
		return "TypeMRC"
	case TypeMMA:
		return "TypeMMA"
	case TypeEFI:
		return "TypeEFI"
	case TypeStruct:
		return "TypeStruct"
	case TypeCMOS:
		return "TypeCMOS"
	case TypeSPD:
		return "TypeSPD"
	case TypeMRCCache:
		return "TypeMRCCache"
	case TypeCMOSLayout:
		return "TypeCMOSLayout"
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

// ReadNameAndAttributes reads the variable CBFS file attribute after the fixed CBFS header
// That is the filename, CBFS Attribute, Hashes, ...
func ReadName(r io.Reader, f *File, size uint32) error {
	b := make([]byte, size)
	n, err := r.Read(b)
	if err != nil {
		Debug("ReadName failed:%v", err)
		return err
	}
	fname := cleanString(string(b))
	Debug("ReadName gets '%s' (%#02x)", fname, b)
	if n != len(b) {
		err = fmt.Errorf("ReadName: got %d, want %d for name", n, len(b))
		Debug("ReadName short: %v", err)
		return err
	}
	// discard trailing NULLs
	z := bytes.Split(b, []byte{0})
	f.Name = string(z[0])
	return nil
}

func ReadAttributes(r io.Reader, f *File) error {
	if f.AttrOffset == 0 {
		return nil
	}

	b := make([]byte, f.SubHeaderOffset-f.AttrOffset)
	n, err := r.Read(b)
	if err != nil {
		Debug("ReadAttributes failed:%v", err)
		return err
	}
	Debug("ReadAttributes gets %#02x", b)
	if n != len(b) {
		err = fmt.Errorf("ReadAttributes: got %d, want %d for name", n, len(b))
		Debug("ReadAttributes short: %v", err)
		return err
	}
	f.Attr = b
	return nil
}

func ReadData(r io.ReadSeeker, f *File) error {
	Debug("ReadData: Seek to %#x", int64(f.RecordStart+f.SubHeaderOffset))
	if _, err := r.Seek(int64(f.RecordStart+f.SubHeaderOffset), io.SeekStart); err != nil {
		return err
	}
	Debug("ReadData: read %#x", f.Size)
	b := make([]byte, f.Size)
	n, err := r.Read(b)
	if err != nil {
		Debug("ReadData failed:%v", err)
		return err
	}
	f.FData = b
	Debug("ReadData gets %#02x", n)
	return nil
}

func ffbyte(s uint32) []byte {
	b := make([]byte, s)
	for i := range b {
		b[i] = 0xff
	}
	return b
}
