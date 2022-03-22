// Copyright 2022 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeOptionRom, Name: "option rom", New: NewOptionROM}); err != nil {
		log.Fatal(err)
	}
}

func NewOptionROM(f *File) (ReadWriter, error) {
	rec := &OptionROMRecord{File: *f}
	return rec, nil
}

func (r *OptionROMRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *OptionROMRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, "none")
}

func (r *OptionROMRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

func (r *OptionROMRecord) GetFile() *File {
	return &r.File
}
