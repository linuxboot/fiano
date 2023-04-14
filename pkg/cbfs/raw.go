// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeRaw, Name: "CBFSRaw", New: NewRaw}); err != nil {
		log.Fatal(err)
	}
}

func NewRaw(f *File) (ReadWriter, error) {
	rec := &RawRecord{File: *f}
	return rec, nil
}

func (r *RawRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *RawRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, r.File.Compression().String())
}

func (r *RawRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

func (r *RawRecord) GetFile() *File {
	return &r.File
}
