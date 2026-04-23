// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// TXT is the TXT element
type TXT struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__TXTS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0           [1]byte          `require:"0" json:"txtReserved0,omitempty"`
	SetNumber           [1]byte          `require:"0" json:"txtSetNumer,omitempty"`
	SInitMinSVNAuth     uint8            `default:"0" json:"txtSVN"`
	Reserved1           [1]byte          `require:"0" json:"txtReserved1,omitempty"`
	ControlFlags        TXTControlFlags  `json:"txtFlags"`
	PwrDownInterval     Duration16In5Sec `json:"txtPwrDownInterval"`
	// PrettyString: PTT CMOS Offset 0
	PTTCMOSOffset0 uint8 `default:"126" json:"txtPTTCMOSOffset0"`
	// PrettyString: PTT CMOS Offset 1
	PTTCMOSOffset1 uint8   `default:"127" json:"txtPTTCMOSOffset1"`
	ACPIBaseOffset uint16  `default:"0x400" json:"txtACPIBaseOffset,omitempty"`
	Reserved2      [2]byte `json:"txtReserved2,omitempty"`
	// PrettyString: ACPI MMIO Offset
	PwrMBaseOffset uint32        `default:"0xFE000000" json:"txtPwrMBaseOffset,omitempty"`
	DigestList     cbnt.HashList `json:"txtDigestList"`
	Reserved3      [3]byte       `require:"0" json:"txtReserved3,omitempty"`

	SegmentCount uint8 `require:"0" json:"txtSegmentCount,omitempty"`
}

// NewTXT returns a new instance of TXT with
// all default values set.
func NewTXT() *TXT {
	s := &TXT{}
	copy(s.ID[:], []byte(StructureIDTXT))
	s.Version = 0x21
	// Set through tag "default":
	s.SInitMinSVNAuth = 0
	// Set through tag "default":
	s.PTTCMOSOffset0 = 126
	// Set through tag "default":
	s.PTTCMOSOffset1 = 127
	// Set through tag "default":
	s.ACPIBaseOffset = 0x400
	// Set through tag "default":
	s.PwrMBaseOffset = 0xFE000000
	// Recursively initializing a child structure:
	s.DigestList = *cbnt.NewHashList()
	// Set through tag "required":
	s.SegmentCount = 0
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *TXT) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}
	// See tag "require"
	for idx := range s.SetNumber {
		if s.SetNumber[idx] != 0 {
			return fmt.Errorf("'SetNumber[%d]' is expected to be 0, but it is %v", idx, s.SetNumber[idx])
		}
	}
	// See tag "require"
	for idx := range s.Reserved1 {
		if s.Reserved1[idx] != 0 {
			return fmt.Errorf("'Reserved1[%d]' is expected to be 0, but it is %v", idx, s.Reserved1[idx])
		}
	}
	// Recursively validating a child structure:
	if err := s.DigestList.Validate(); err != nil {
		return fmt.Errorf("error on field 'DigestList': %w", err)
	}
	// See tag "require"
	for idx := range s.Reserved3 {
		if s.Reserved3[idx] != 0 {
			return fmt.Errorf("'Reserved3[%d]' is expected to be 0, but it is %v", idx, s.Reserved3[idx])
		}
	}
	// See tag "require"
	if s.SegmentCount != 0 {
		return fmt.Errorf("field 'SegmentCount' expects value '0', but has %v", s.SegmentCount)
	}

	return nil
}

func (s *TXT) Layout() []cbnt.LayoutField {
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
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    2,
			Name:  "Set Number",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.SetNumber },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    3,
			Name:  "S Init Min SVN Auth",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.SInitMinSVNAuth },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "Reserved 1",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved1 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    5,
			Name:  "Control Flags",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.ControlFlags },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "Pwr Down Interval",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.PwrDownInterval },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    7,
			Name:  "PTT CMOS Offset 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.PTTCMOSOffset0 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    8,
			Name:  "PTT CMOS Offset 1",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.PTTCMOSOffset1 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    9,
			Name:  "ACPI Base Offset",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.ACPIBaseOffset },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    10,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Reserved2 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    11,
			Name:  "ACPI MMIO Offset",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.PwrMBaseOffset },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    12,
			Name:  "Digest List",
			Size:  func() uint64 { return s.DigestList.TotalSize() },
			Value: func() any { return &s.DigestList },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    13,
			Name:  "Reserved 3",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &s.Reserved3 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    14,
			Name:  "Segment Count",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.SegmentCount },
			Type:  cbnt.ManifestFieldEndValue,
		},
	}
}

func (s *TXT) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("TXT: %v", err)
	}

	return ret, nil
}

func (s *TXT) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("TXT: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *TXT) GetStructInfo() cbnt.StructInfoCBNT {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *TXT) SetStructInfo(newStructInfo cbnt.StructInfoCBNT) {
	s.StructInfoCBNT = newStructInfo
}

// Dummy helper to comply with requirements of cbnt.Structure interface
func (s *TXT) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the TXT from 'r' in format defined in the document #575623.
func (s *TXT) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *TXT) RehashRecursive() {
	s.DigestList.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *TXT) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the TXT into 'w' in format defined in
// the document #575623.
func (s *TXT) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the TXT.
func (s *TXT) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *TXT) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "TXT", opts...)
}

type Duration16In5Sec uint16

// PrettyString returns the bits of the flags in an easy-to-read format.
func (d Duration16In5Sec) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return d.String()
}

// TotalSize returns the total size measured through binary.Size.
func (d Duration16In5Sec) TotalSize() uint64 {
	return uint64(binary.Size(d))
}

// WriteTo writes the Duration16In5Sec into 'w' in binary format.
func (d Duration16In5Sec) WriteTo(w io.Writer) (int64, error) {
	return int64(d.TotalSize()), binary.Write(w, binary.LittleEndian, d)
}

// ReadFrom reads the Duration16In5Sec from 'r' in binary format.
func (d Duration16In5Sec) ReadFrom(r io.Reader) (int64, error) {
	return int64(d.TotalSize()), binary.Read(r, binary.LittleEndian, d)
}

// Duration calculates a given time in multiple of 5 seconds.
func (d Duration16In5Sec) Duration() time.Duration {
	return time.Second * 5 * time.Duration(d)
}

func (d Duration16In5Sec) String() string {
	if d == 0 {
		return "0 (infinite)"
	}
	return fmt.Sprintf("%d (%s)", d, d.Duration().String())
}
