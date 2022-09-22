// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"bytes"
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: 2, Name: "CBFSMaster", New: NewMaster}); err != nil {
		log.Fatal(err)
	}
}

func NewMaster(f *File) (ReadWriter, error) {
	Debug("NewMaster: %+v, %x", f, f)
	r := &MasterRecord{File: *f}
	return r, nil
}

func (r *MasterRecord) Read(in io.ReadSeeker) error {
	dump := &bytes.Buffer{}
	n, err := io.Copy(dump, in)
	if err != nil {
		return err
	}
	Debug("MasterRecord (%d bytes)\n   %+v\n   %x", n, r, dump)
	Debug("MasterRecord Header %v at %v", r.MasterHeader, r.Offset)
	if err := Read(in, &r.MasterHeader); err != nil {
		Debug("MasterRecord read from %v: %v", r.Offset, err)
		return err
	}
	Debug("Got header %s offset %#x", r.String(), r.Offset)
	return nil
}

func (r *MasterRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, "none")
}

func (r *MasterRecord) Write(w io.Writer) error {
	return Write(w, r.MasterHeader)
}

func (r *MasterRecord) GetFile() *File {
	return &r.File
}
