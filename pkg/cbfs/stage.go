// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
)

func init() {
	if err := RegisterFileReader(&SegReader{Type: TypeLegacyStage, Name: "LegacyStage", New: NewLegacyStageRecord}); err != nil {
		log.Fatal(err)
	}
	if err := RegisterFileReader(&SegReader{Type: TypeStage, Name: "Stage", New: NewStageRecord}); err != nil {
		log.Fatal(err)
	}
}

func NewLegacyStageRecord(f *File) (ReadWriter, error) {
	r := &LegacyStageRecord{File: *f}
	return r, nil
}

func (r *LegacyStageRecord) Read(in io.ReadSeeker) error {
	if err := ReadLE(in, &r.StageHeader); err != nil {
		Debug("StageHeader read: %v", err)
		return err
	}
	Debug("Got StageHeader %s, data is %d bytes", r.String(), r.StageHeader.Size)
	r.Data = make([]byte, r.StageHeader.Size)
	n, err := in.Read(r.Data)
	if err != nil {
		return err
	}
	Debug("Stage read %d bytes", n)
	return nil
}

type mStage struct {
	Name        string
	Start       uint32
	Size        uint32
	Type        string
	Compression string
}

func (h *LegacyStageRecord) MarshalJSON() ([]byte, error) {
	s := mStage{
		Name:        h.File.Name,
		Start:       h.RecordStart,
		Size:        h.Size,
		Type:        h.Type.String(),
		Compression: h.File.Compression().String(),
	}

	return json.Marshal(s)
}

func (h *StageHeader) String() string {
	return fmt.Sprintf("Compression %#x Entry %#x LoadAddress %#x Size %#x MemSize %#x",
		h.Compression,
		h.Entry,
		h.LoadAddress,
		h.Size,
		h.MemSize)
}

func (h *LegacyStageRecord) String() string {
	return recString(h.File.Name, h.RecordStart, h.Type.String(), h.Size, h.File.Compression().String())
}

func (r *LegacyStageRecord) Write(w io.Writer) error {
	if err := WriteLE(w, r.StageHeader); err != nil {
		return err
	}

	return Write(w, r.Data)
}

func (r *LegacyStageRecord) GetFile() *File {
	return &r.File
}

func NewStageRecord(f *File) (ReadWriter, error) {
	r := &StageRecord{File: *f}
	return r, nil
}

func (r *StageRecord) Read(in io.ReadSeeker) error {
	return nil
}

func (h *FileAttrStageHeader) String() string {
	return fmt.Sprintf("Size %#x LoadAddress %#x EntryOffset %#x MemSize %#x",
		h.Size,
		h.LoadAddress,
		h.EntryOffset,
		h.MemSize)
}

func (h *StageRecord) String() string {
	return recString(h.File.Name, h.RecordStart, h.Type.String(), h.File.Size, h.File.Compression().String())
}

func (r *StageRecord) Write(w io.Writer) error {
	return Write(w, r.Data)
}

func (r *StageRecord) GetFile() *File {
	return &r.File
}
