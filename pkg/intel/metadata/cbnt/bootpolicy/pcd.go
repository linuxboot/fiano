// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// PCD holds various Platform Config Data.
type PCD struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__PCDS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0           [2]byte `json:"pcdReserved0,omitempty"`
	SizeOfData          [2]byte `json:"pcdSizeOfData,omitempty"`
	Data                []byte  `json:"pcdData"`
	PDRS                *PDRS   `json:"pcdPDRS,omitempty"`
	CNBS                *CNBS   `json:"pcdCNBS,omitempty"`
}

// NewPCD returns a new instance of PCD with
// all default values set.
func NewPCD() *PCD {
	s := &PCD{}
	copy(s.ID[:], []byte(StructureIDPCD))
	s.Version = 0x20
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *PCD) Validate() error {
	if s.Version < 0x22 {
		return nil
	}

	if s.PDRS != nil {
		if err := s.PDRS.Validate(); err != nil {
			return fmt.Errorf("error on field 'PDRS': %w", err)
		}
	}
	if s.CNBS != nil {
		if err := s.CNBS.Validate(); err != nil {
			return fmt.Errorf("error on field 'CNBS': %w", err)
		}
	}
	return nil
}

func (s *PCD) Layout() []cbnt.LayoutField {
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
			Name:  "Size Of Data",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.SizeOfData },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:   3,
			Name: "Data",
			Size: func() uint64 {
				size := binary.LittleEndian.Uint16(s.SizeOfData[:])
				if size == 0 && len(s.Data) != 0 {
					size = uint16(len(s.Data))
				}
				if s.ElementSize != 0 {
					resSize, err := s.SizeOf(1)
					if err != nil {
						return uint64(size)
					}

					sodSize, err := s.SizeOf(2)
					if err != nil {
						return uint64(size)
					}
					base := s.StructInfoCBNT.TotalSize() + resSize + sodSize
					guessedSize := base + uint64(size)
					if guessedSize != uint64(s.ElementSize) {
						size = s.StructInfoCBNT.ElementSize - uint16(s.StructInfoCBNT.TotalSize()) - uint16(resSize) - uint16(sodSize)
					}
				}
				return uint64(size)
			},
			Value: func() any { return &s.Data },
			Type:  cbnt.ManifestFieldArrayDynamicWithSize,
		},
	}
}

func (s *PCD) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PCD: %v", err)
	}

	return ret, nil
}

func (s *PCD) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PCD: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PCD) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PCD) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// Dummy helper to comply with cbnt.Structure interface
func (s *PCD) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the PCD from 'r' in format defined in the document #575623.
func (s *PCD) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	n, err := s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
	if err != nil {
		return n, err
	}

	if s.Version > 0x21 {
		rn := bytes.NewReader(s.Data)
		structInfoSize := binary.Size(cbnt.StructInfoCBNT{})

		for rn.Len() >= structInfoSize {
			var structInfo cbnt.StructInfoCBNT
			if err := binary.Read(rn, binary.LittleEndian, &structInfo); err != nil {
				return n, err
			}

			switch structInfo.ID.String() {
			case StructureIDPDRS:
				p := NewPDRS()
				p.SetStructInfo(structInfo)
				if _, err := p.ReadFromHelper(rn, false); err != nil {
					return n, err
				}
				s.PDRS = p
			case StructureIDCNBS:
				c := NewCNBS()
				c.SetStructInfo(structInfo)
				if _, err := c.ReadFromHelper(rn, false); err != nil {
					return n, err
				}
				s.CNBS = c
			default:
				return n, nil
			}
		}
	}

	return n, nil

}

// RehashRecursive calls Rehash (see below) recursively.
func (s *PCD) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *PCD) Rehash() {
	if s.Version > 0x21 && len(s.Data) == 0 {
		var out bytes.Buffer
		if s.PDRS != nil {
			_, _ = s.PDRS.WriteTo(&out)
		}
		if s.CNBS != nil {
			_, _ = s.CNBS.WriteTo(&out)
		}
		if out.Len() > 0 {
			s.Data = out.Bytes()
			binary.LittleEndian.PutUint16(s.SizeOfData[:], uint16(len(s.Data)))
		}
	}
	s.Variable0 = 0
	s.ElementSize = uint16(s.StructInfoCBNT.TotalSize() + 2 + 2 + uint64(len(s.Data)))
}

// WriteTo writes the PCD into 'w' in format defined in
// the document #575623.
func (s *PCD) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the PCD.
func (s *PCD) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	if s.ElementSize != 0 {
		return uint64(s.ElementSize)
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PCD) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	base := s.Common.PrettyString(depth, withHeader, s, "PCD", opts...)

	var lines []string
	lines = append(lines, base)
	if s.Version > 0x21 && s.PDRS != nil {
		lines = append(lines, s.PDRS.PrettyString(depth, true, opts...))
	}
	if s.Version > 0x21 && s.CNBS != nil {
		lines = append(lines, s.CNBS.PrettyString(depth, true, opts...))
	}

	return strings.Join(lines, "\n")
}

// PDRS
type PDRS struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__PDRS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Data                []byte `json:"pdrsData"`
}

// NewPDRS returns a new instance of PDRS with all default values set.
func NewPDRS() *PDRS {
	s := &PDRS{}
	copy(s.ID[:], []byte(StructureIDPDRS))
	s.Version = 0x20
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *PDRS) Validate() error {
	return nil
}

func (s *PDRS) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfoCBNT.TotalSize() },
			Value: func() any { return &s.StructInfoCBNT },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   1,
			Name: "Data",
			Size: func() uint64 {
				if s.ElementSize != 0 {
					return uint64(s.ElementSize)
				}
				return uint64(len(s.Data))
			},
			Value: func() any { return &s.Data },
			Type:  cbnt.ManifestFieldArrayDynamicWithSize,
		},
	}
}

func (s *PDRS) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PDRS: %v", err)
	}

	return ret, nil
}

func (s *PDRS) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PDRS: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PDRS) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PDRS) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// ReadFrom reads the PDRS from 'r' in format defined in the document #575623.
func (s *PDRS) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the PDRS from 'r' in format defined in the document #575623.
func (s *PDRS) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *PDRS) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *PDRS) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(len(s.Data))
}

// WriteTo writes the PDRS into 'w' in format defined in
// the document #575623.
func (s *PDRS) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the PDRS.
func (s *PDRS) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	if s.ElementSize != 0 {
		return uint64(s.StructInfo().TotalSize()) + uint64(s.ElementSize)
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PDRS) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "PDRS", opts...)
}

// CNBS
type CNBS struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__CNBS__" version:"0x20" var0:"0" var1:"12"`
	BufferData          IBBSegment `json:"seIBBSegment"`
}

// NewCNBS returns a new instance of CNBS with all default values set.
func NewCNBS() *CNBS {
	s := &CNBS{}
	copy(s.ID[:], []byte(StructureIDCNBS))
	s.Version = 0x20
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *CNBS) Validate() error {
	if err := s.BufferData.Validate(); err != nil {
		return fmt.Errorf("error on field 'BufferData': %w", err)
	}

	return nil
}

func (s *CNBS) Layout() []cbnt.LayoutField {
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
			Name:  "Buffer Data",
			Size:  func() uint64 { return s.BufferData.TotalSize() },
			Value: func() any { return &s.BufferData },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *CNBS) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("CNBS: %v", err)
	}

	return ret, nil
}

func (s *CNBS) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("CNBS: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *CNBS) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *CNBS) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// ReadFrom reads the CNBS from 'r' in format defined in the document #575623.
func (s *CNBS) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the CNBS from 'r' in format defined in the document #575623.
func (s *CNBS) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *CNBS) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *CNBS) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.BufferData.TotalSize())
}

// WriteTo writes the CNBS into 'w' in format defined in
// the document #575623.
func (s *CNBS) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the CNBS.
func (s *CNBS) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	if s.ElementSize != 0 {
		return uint64(s.StructInfo().TotalSize()) + uint64(s.ElementSize)
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *CNBS) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "CNBS", opts...)
}
