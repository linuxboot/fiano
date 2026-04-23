// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type Reserved struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__PFRS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
	ReservedData        [32]byte `json:"ReservedData"`
}

// NewReserved returns a new instance of Reserved with
// all default values set.
func NewReserved() *Reserved {
	// Only present in CBnT, thus we assume StructInfoCBNT.
	s := &Reserved{}
	copy(s.ID[:], []byte(StructureIDReserved))
	s.Version = 0x21
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Reserved) Validate() error {

	return nil
}

func (s *Reserved) Layout() []cbnt.LayoutField {
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
			Name:  "Reserved Data",
			Size:  func() uint64 { return 32 },
			Value: func() any { return &s.ReservedData },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
	}
}

func (s *Reserved) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Reserved: %v", err)
	}

	return ret, nil
}

func (s *Reserved) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Reserved: %v", err)
	}

	return ret, nil
}

// StructureIDReserved is the StructureID (in terms of
// the document #575623) of element 'Reserved'.
const StructureIDReserved = "__PFRS__"

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Reserved) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Reserved) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// Dummy helper to comply with cbnt.Structure interface
func (s *Reserved) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the Reserved from 'r' in format defined in the document #575623.
func (s *Reserved) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Reserved) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Reserved) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the Reserved into 'w' in format defined in
// the document #575623.
func (s *Reserved) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the Reserved.
func (s *Reserved) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Reserved) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "Reserved", opts...)
}
