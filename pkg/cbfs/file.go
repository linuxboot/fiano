// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var CbfsHeaderMagicNotFound = errors.New("CBFS header magic doesn't match")

func (f *File) MarshalJSON() ([]byte, error) {
	return json.Marshal(mFile{
		Name:  f.Name,
		Start: f.RecordStart,
		Size:  f.FileHeader.Size,
		Type:  f.FileHeader.Type.String(),
	})
}

// NewFile reads in the CBFS file at current offset
// On success it seeks to the end of the file.
// On error the current offset withing the ReadSeeker is undefined.
func NewFile(r io.ReadSeeker) (*File, error) {
	var f File
	off, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	f.RecordStart = uint32(off)

	err = Read(r, &f.FileHeader)
	if err != nil {
		return nil, err
	}
	if string(f.Magic[:]) != FileMagic {
		return nil, CbfsHeaderMagicNotFound
	}
	Debug("It is %v type %v", f, f.Type)

	Debug("Starting at %#02x", f.RecordStart)
	nameStart, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("Getting file offset for name: %v", err)
	}

	var nameSize uint32
	if f.AttrOffset == 0 {
		nameSize = f.SubHeaderOffset - (uint32(nameStart) - f.RecordStart)
	} else {
		nameSize = f.AttrOffset - (uint32(nameStart) - f.RecordStart)
	}
	if err := ReadName(r, &f, nameSize); err != nil {
		return nil, err
	}
	if err := ReadAttributes(r, &f); err != nil {
		return nil, err
	}
	if err := ReadData(r, &f); err != nil {
		return nil, err
	}

	return &f, nil
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
	Debug("ReadName stripped: '%s'", z)
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
