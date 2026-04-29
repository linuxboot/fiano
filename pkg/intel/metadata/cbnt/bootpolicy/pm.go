// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type PM interface {
	cbnt.Structure
}

// NewPM returns a new instance of PM with
// all default values set.
func NewPM(bgv cbnt.BootGuardVersion) (PM, error) {
	switch bgv {
	case cbnt.Version10:
		s := &PMBG{}
		copy(s.ID[:], []byte(StructureIDPM))
		s.Version = 0x10
		return s, nil
	case cbnt.Version20, cbnt.Version21:
		s := &PMCBnT{}
		copy(s.ID[:], []byte(StructureIDPM))
		s.Version = 0x20
		s.Rehash()
		return s, nil
	default:
		return nil, fmt.Errorf("version not supported")
	}
}

type PMCBnT struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__PMDA__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0           [2]byte `require:"0" json:"pcReserved0,omitempty"`
	DataSize            [2]byte `json:"pcDataSize"`
	Data                []byte  `json:"pcData"`
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *PMCBnT) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}

	return nil
}

// Layout returns the structure's layout descriptor
func (s *PMCBnT) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfoCBNT.TotalSize() },
			Value: func() any { return &s.StructInfoCBNT },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "Reserved 0",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    2,
			Name:  "Data Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.DataSize },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    3,
			Name:  "Data",
			Size:  func() uint64 { return uint64(binary.Size(uint16(0))) + uint64(binary.Size(s.DataSize)) },
			Value: func() any { return &s.Data },
			Type:  cbnt.ManifestFieldArrayDynamicWithPrefix,
		},
	}
}

// SizeOf returns the size of the structure's field of a given id.
func (s *PMCBnT) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PM: %v", err)
	}

	return ret, nil
}

// OffsetOf returns the offset of the structure's field of a given id.
func (s *PMCBnT) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PM: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PMCBnT) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PMCBnT) SetStructInfo(newStructInfo cbnt.StructInfoCBNT) {
	s.StructInfoCBNT = newStructInfo
}

// Has to be here to fullfil Structure interface requirements.
// Reads the whole data.
func (s *PMCBnT) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the PM from 'r' in format defined in the document #575623.
func (s *PMCBnT) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *PMCBnT) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *PMCBnT) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.Common.TotalSize(s))
}

// WriteTo writes the PM into 'w' in format defined in
// the document #575623.
func (s *PMCBnT) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the PM.
func (s *PMCBnT) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PMCBnT) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "PM", opts...)
}

type PMBG struct {
	cbnt.StructInfoBG `id:"__PMDA__" version:"0x10"`
	DataSize          uint16 `json:"pcDataSize"`
	Data              []byte `json:"pcData"`
}

// Layout returns the structure's layout descriptor
func (s *PMBG) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfoBG.TotalSize() },
			Value: func() any { return &s.StructInfoBG },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "Data Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.DataSize },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    2,
			Name:  "Data",
			Size:  func() uint64 { return uint64(binary.Size(uint16(0))) + uint64(s.DataSize) },
			Value: func() any { return &s.Data },
			Type:  cbnt.ManifestFieldArrayDynamicWithPrefix,
		},
	}
}

// Validate implements Structure.Validate()
func (s *PMBG) Validate() error {
	// dummy
	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PMBG) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoBG
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PMBG) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoBG = newStructInfo.(cbnt.StructInfoBG)
}

// Has to be here to fullfil Structure interface requirements.
// Reads the whole data.
func (s *PMBG) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the PM from 'r' in format defined in the document #575623.
func (s *PMBG) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// WriteTo writes the PM into 'w' in format defined in
// the document #575623.
func (s *PMBG) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

// SizeOf returns the size of the structure's field of a given id.
func (s *PMBG) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PM: %v", err)
	}

	return ret, nil
}

// OffsetOf returns the offset of the structure's field of a given id.
func (s *PMBG) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PM: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the PM.
func (s *PMBG) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PMBG) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "PM", opts...)
}
