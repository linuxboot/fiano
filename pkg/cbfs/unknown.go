// Copyright 2018-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
)

func NewUnknownRecord(f *File) (ReadWriter, error) {
	r := &UnknownRecord{File: *f}
	Debug("Got header %v", r.String())
	r.Attr = make([]byte, 16)
	r.FData = ffbyte(f.Size)
	return r, nil
}

func (r *UnknownRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *UnknownRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.File.Type.String(), r.Size, "none")
}

func (r *UnknownRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

func (r *UnknownRecord) GetFile() *File {
	return &r.File
}
