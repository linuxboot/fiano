// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type BPMH interface {
	cbnt.Structure
}

// NewBPMH returns a new instance of BPMH with
// all default values set.
func NewBPMH(bgv cbnt.BootGuardVersion) (BPMH, error) {
	switch bgv {
	case cbnt.Version10:
		s := &BPMHBG{}
		copy(s.ID[:], []byte(StructureIDBPMH))
		s.Version = 0x10
		return s, nil
	case cbnt.Version20:
		s := &BPMHCBnT{}
		copy(s.ID[:], []byte(StructureIDBPMH))
		s.Version = 0x23
		s.Rehash()
		return s, nil
	case cbnt.Version21:
		s := &BPMHCBnT{}
		copy(s.ID[:], []byte(StructureIDBPMH))
		s.Version = 0x24
		s.Rehash()
		return s, nil
	default:
		return nil, fmt.Errorf("version not supported")
	}
}

// BPMH is the header of boot policy manifest
type BPMHCBnT struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__ACBP__" version:"0x23" var0:"0x20" var1:"uint16(s.TotalSize())"`

	KeySignatureOffset uint16 `json:"bpmhKeySignatureOffset"`

	BPMRevision uint8 `json:"bpmhRevision"`

	// BPMSVN is BPM security version number
	//
	// PrettyString: BPM SVN
	BPMSVN cbnt.SVN `json:"bpmhSNV"`

	// ACMSVNAuth is authorized ACM security version number
	//
	// PrettyString: ACM SVN Auth
	ACMSVNAuth cbnt.SVN `json:"bpmhACMSVN"`

	Reserved0 [1]byte `require:"0" json:"bpmhReserved0,omitempty"`

	NEMDataStack Size4K `json:"bpmhNEMStackSize"`
}

func (s *BPMHCBnT) Layout() []cbnt.LayoutField {
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
			Name:  "Key Signature Offset",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.KeySignatureOffset },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "BPM Revision",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.BPMRevision },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "BPM SVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.BPMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "ACM SVN Auth",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.ACMSVNAuth },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Reserved 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    6,
			Name:  "NEM Data Stack",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.NEMDataStack },
			Type:  cbnt.ManifestFieldEndValue,
		},
	}
}

func (s *BPMHCBnT) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("BPMH: %v", err)
	}

	return ret, nil
}

func (s *BPMHCBnT) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("BPMH: %v", err)
	}

	return ret, nil
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *BPMHCBnT) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}

	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BPMHCBnT) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BPMHCBnT) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// Has to be here to fullfil Structure interface requirements.
// Reads the whole data.
func (s *BPMHCBnT) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the BPMH from 'r' in format defined in the document #575623.
func (s *BPMHCBnT) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *BPMHCBnT) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *BPMHCBnT) Rehash() {
	s.Variable0 = 0x20
	s.ElementSize = uint16(s.Common.TotalSize(s))
}

// WriteTo writes the BPMH into 'w' in format defined in
// the document #575623.
func (s *BPMHCBnT) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the BPMH.
func (s *BPMHCBnT) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *BPMHCBnT) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "BPMH", opts...)
}

type BPMHBG struct {
	cbnt.StructInfoBG `id:"__ACBP__" version:"0x10"`

	HdrStructVersion uint8 `json:"HdrStructVersion"`

	PMBPMVersion uint8 `json:"bpmhRevision"`

	// PrettyString: BPM SVN
	BPMSVN cbnt.SVN `json:"bpmhSNV"`
	// PrettyString: ACM SVN Auth
	ACMSVNAuth cbnt.SVN `json:"bpmhACMSVN"`

	Reserved0 [1]byte `require:"0" json:"bpmhReserved0,omitempty"`

	NEMDataStack Size4K `json:"bpmhNEMStackSize"`
}

func (s *BPMHBG) Layout() []cbnt.LayoutField {
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
			Name:  "Hdr Structure Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.HdrStructVersion },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "PMBPM Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.PMBPMVersion },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "BPM SVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.BPMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "ACM SVN Auth",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.ACMSVNAuth },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Reserved 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    6,
			Name:  "NEM Data Stack",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.NEMDataStack },
			Type:  cbnt.ManifestFieldEndValue,
		},
	}
}

func (s *BPMHBG) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("BPMH: %v", err)
	}

	return ret, nil
}

func (s *BPMHBG) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("BPMH: %v", err)
	}

	return ret, nil
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *BPMHBG) Validate() error {
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}

	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BPMHBG) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoBG
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BPMHBG) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoBG = newStructInfo.(cbnt.StructInfoBG)
}

// Has to be here to fullfil Structure interface requirements.
// Reads the whole data.
func (s *BPMHBG) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the BPMH from 'r' in format defined in the document #575623.
func (s *BPMHBG) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// WriteTo writes the BPMH into 'w' in format defined in
// the document #575623.
func (s *BPMHBG) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the BPMH.
func (s *BPMHBG) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *BPMHBG) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "BPMH", opts...)
}

type Size4K uint16

// InBytes returns the size in bytes.
func (v Size4K) InBytes() uint32 {
	return uint32(v) * 4096
}

// NewSize4K returns the given size as multiple of 4K
func NewSize4K(size uint32) Size4K {
	return Size4K(size / 4096)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v Size4K) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Size 4 K", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "In Bytes", "", v.InBytes(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v Size4K) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the Size4K into 'w' in binary format.
func (v Size4K) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the Size4K from 'r' in binary format.
func (v Size4K) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}
