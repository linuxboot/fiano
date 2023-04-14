// Copyright 2022 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeBootSplash, Name: "bootsplash", New: NewBootSplash}); err != nil {
		log.Fatal(err)
	}
}

// NewBootSplash returns a ReadWriter interface for the CBFS type TypeBootSplash
func NewBootSplash(f *File) (ReadWriter, error) {
	rec := &BootSplashRecord{File: *f}
	return rec, nil
}

func (r *BootSplashRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (r *BootSplashRecord) String() string {
	return recString(r.File.Name, r.RecordStart, r.Type.String(), r.Size, r.File.Compression().String())
}

func (r *BootSplashRecord) Write(w io.Writer) error {
	return Write(w, r.FData)
}

// File returns a pointer to the corresponding File
func (r *BootSplashRecord) GetFile() *File {
	return &r.File
}
