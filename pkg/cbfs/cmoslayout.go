// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeCMOSLayout, Name: "CBFSCMOSLayout", New: NewCMOSLayout}); err != nil {
		log.Fatal(err)
	}
}

func NewCMOSLayout(f *File) (ReadWriter, error) {
	rec := &CMOSLayoutRecord{File: *f}
	return rec, nil
}

func (r *CMOSLayoutRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *CMOSLayoutRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, r.File.Compression().String())
}

func (r *CMOSLayoutRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

func (r *CMOSLayoutRecord) GetFile() *File {
	return &r.File
}
