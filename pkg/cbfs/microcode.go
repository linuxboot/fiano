// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeMicroCode, Name: "microcode", New: NewMicrocode}); err != nil {
		log.Fatal(err)
	}
}

//NewMicrocode returns a ReadWriter interface for the CBFS type TypeMicroCode
func NewMicrocode(f *File) (ReadWriter, error) {
	rec := &MicrocodeRecord{File: *f}
	return rec, nil
}

func (r *MicrocodeRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *MicrocodeRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, r.File.Compression().String())
}

func (r *MicrocodeRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

//Header returns a pointer to the corresponding File
func (r *MicrocodeRecord) GetFile() *File {
	return &r.File
}
