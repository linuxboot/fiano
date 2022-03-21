// Copyright 2022 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeCMOS, Name: "cmos", New: NewCMOS}); err != nil {
		log.Fatal(err)
	}
}

func NewCMOS(f *File) (ReadWriter, error) {
	rec := &CMOSRecord{File: *f}
	return rec, nil
}

func (r *CMOSRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *CMOSRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, "none")
}

func (r *CMOSRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

func (r *CMOSRecord) GetFile() *File {
	return &r.File
}
