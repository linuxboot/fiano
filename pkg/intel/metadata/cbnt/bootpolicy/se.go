// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"io"
	"math"
	"strings"
	"time"
)

// IBBSegment defines a single IBB segment
type IBBSegment struct {
	cbnt.Common
	Reserved [2]byte `require:"0" json:"ibbSegReserved"`
	Flags    uint16  `json:"ibbSegFlags"`
	Base     uint32  `json:"ibbSegBase"`
	Size     uint32  `json:"ibbSegSize"`
}

// NewIBBSegment returns a new instance of IBBSegment with
// all default values set.
func NewIBBSegment() *IBBSegment {
	s := &IBBSegment{}
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *IBBSegment) Validate() error {
	// See tag "require"
	for idx := range s.Reserved {
		if s.Reserved[idx] != 0 {
			return fmt.Errorf("'Reserved[%d]' is expected to be 0, but it is %v", idx, s.Reserved[idx])
		}
	}

	return nil
}

func (s *IBBSegment) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Reserved",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Reserved },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Flags",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Flags },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Base",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Base },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Size",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Size },
			Type:  cbnt.ManifestFieldEndValue,
		},
	}
}

func (s *IBBSegment) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("IBBSegment: %v", err)
	}

	return ret, nil
}

func (s *IBBSegment) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("IBBSegment: %v", err)
	}

	return ret, nil
}

// ReadFrom reads the IBBSegment from 'r' in format defined in the document #575623.
func (s *IBBSegment) ReadFrom(r io.Reader) (int64, error) {
	return s.Common.ReadFrom(r, s)
}

// WriteTo writes the IBBSegment into 'w' in format defined in
// the document #575623.
func (s *IBBSegment) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the IBBSegment.
func (s *IBBSegment) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *IBBSegment) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "IBB Segment", opts...)
}

type SE interface {
	cbnt.Structure
}

// SE is an IBB segments element
//
// PrettyString: IBB Segments Element
type SECBnT struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__IBBS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0           [1]byte   `require:"0" json:"seReserved0,omitempty"`
	SetNumber           uint8     `require:"0" json:"seSetNumber,omitempty"`
	Reserved1           [1]byte   `require:"0" json:"seReserved1,omitempty"`
	PBETValue           PBETValue `json:"sePBETValue"`
	Flags               SEFlags   `json:"seFlags"`

	// IBBMCHBAR <TO BE DOCUMENTED>
	// PrettyString: IBB MCHBAR
	IBBMCHBAR uint64 `json:"seIBBMCHBAR"`

	// VTdBAR <TO BE DOCUMENTED>
	// PrettyString: VT-d BAR
	VTdBAR uint64 `json:"seVTdBAR"`

	// DMAProtBase0 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 0 Base Address
	DMAProtBase0 uint32 `json:"seDMAProtBase0"`

	// DMAProtLimit0 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 0 Limit Address
	DMAProtLimit0 uint32 `json:"seDMAProtLimit0"`

	// DMAProtBase1 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 1 Base Address
	DMAProtBase1 uint64 `json:"seDMAProtBase1"`

	// DMAProtLimit1 <TO BE DOCUMENTED>
	// PrettyString: DMA Protection 2 Limit Address
	DMAProtLimit1 uint64 `json:"seDMAProtLimit1"`

	PostIBBHash cbnt.HashStructure `json:"sePostIBBHash"`

	IBBEntryPoint uint32 `json:"seIBBEntry"`

	DigestList cbnt.HashList `json:"seDigestList"`

	OBBHash cbnt.HashStructure `json:"seOBBHash"`

	Reserved2 [3]byte `require:"0" json:"seReserved2,omitempty"`

	IBBSegments []IBBSegment `countType:"uint8" json:"seIBBSegments,omitempty"`
}

// NewSE returns a new instance of SE with
// all default values set.
func NewSE(bgv cbnt.BootGuardVersion) (SE, error) {
	switch bgv {
	case cbnt.Version10:
		s := &SEBG{}
		// See 'default' in HashStructure for BG in legacy package
		hashAlg := 0x0b
		copy(s.ID[:], []byte(StructureIDSE))
		s.Version = 0x10
		// Recursively initializing a child structure:
		s.PostIBBHash = *cbnt.NewHashStructureFill(cbnt.Algorithm(hashAlg))
		// Recursively initializing a child structure:
		s.Digest = *cbnt.NewHashStructure(cbnt.Algorithm(hashAlg))
		return s, nil
	case cbnt.Version20, cbnt.Version21:
		s := &SECBnT{}
		// See 'default' in HashStructure for CBNT
		hashAlg := 0x10
		copy(s.ID[:], []byte(StructureIDSE))
		// Yes, conditional statement inside of switch case
		// seems hacky. But it saves us from revriting the whole
		// block an changing just one value (version)
		if bgv == cbnt.Version20 {
			s.Version = 0x20
		} else {
			s.Version = 0x21
		}
		// Set through tag "required":
		s.SetNumber = 0
		// Recursively initializing a child structure:
		s.PostIBBHash = *cbnt.NewHashStructure(cbnt.Algorithm(hashAlg))
		// Recursively initializing a child structure:
		s.DigestList = *cbnt.NewHashList()
		// Recursively initializing a child structure:
		s.OBBHash = *cbnt.NewHashStructure(cbnt.Algorithm(hashAlg))
		s.Rehash()
		return s, nil

	default:
		return nil, fmt.Errorf("version not supported")
	}
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *SECBnT) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}
	// See tag "require"
	if s.SetNumber != 0 {
		return fmt.Errorf("field 'SetNumber' expects value '0', but has %v", s.SetNumber)
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
	for idx := range s.Reserved2 {
		if s.Reserved2[idx] != 0 {
			return fmt.Errorf("'Reserved2[%d]' is expected to be 0, but it is %v", idx, s.Reserved2[idx])
		}
	}

	return nil
}

func (s *SECBnT) Layout() []cbnt.LayoutField {
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
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Reserved 1",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved1 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    4,
			Name:  "PBET Value",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.PBETValue },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Flags",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Flags },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "IBB MCHBAR",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.IBBMCHBAR },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    7,
			Name:  "VT-d BAR",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.VTdBAR },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    8,
			Name:  "DMA Protection 0 Base Address",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.DMAProtBase0 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    9,
			Name:  "DMA Protection 0 Limit Address",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.DMAProtLimit0 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    10,
			Name:  "DMA Protection 1 Base Address",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.DMAProtBase1 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    11,
			Name:  "DMA Protection 2 Limit Address",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.DMAProtLimit1 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    12,
			Name:  "Post IBB Hash",
			Size:  func() uint64 { return s.PostIBBHash.TotalSize() },
			Value: func() any { return &s.PostIBBHash },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    13,
			Name:  "IBB Entry Point",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.IBBEntryPoint },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    14,
			Name:  "Digest List",
			Size:  func() uint64 { return s.DigestList.TotalSize() },
			Value: func() any { return &s.DigestList },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    15,
			Name:  "OBB Hash",
			Size:  func() uint64 { return s.OBBHash.TotalSize() },
			Value: func() any { return &s.OBBHash },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    16,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &s.Reserved2 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:   17,
			Name: fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint8(0)))
				for idx := range s.IBBSegments {
					size += s.IBBSegments[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.IBBSegments },
			Type:  cbnt.ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint8
				if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'IBBSegments': %w", err)
				}
				totalN := int64(binary.Size(count))
				s.IBBSegments = make([]IBBSegment, count)
				for idx := range s.IBBSegments {
					n, err := s.IBBSegments[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'IBBSegments[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
			WriteList: func(w io.Writer) (int64, error) {
				count := uint8(len(s.IBBSegments))
				if err := binary.Write(w, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to write the count for field 'IBBSegments': %w", err)
				}
				totalN := int64(binary.Size(count))
				for idx := range s.IBBSegments {
					n, err := s.IBBSegments[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'IBBSegments[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
		},
	}
}

func (s *SECBnT) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("SE: %v", err)
	}

	return ret, nil
}

func (s *SECBnT) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("SE: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *SECBnT) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *SECBnT) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// Has to be here to fullfil the reuirements of cbnt.Structure
func (s *SECBnT) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the SE from 'r' in format defined in the document #575623.
func (s *SECBnT) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *SECBnT) RehashRecursive() {
	s.DigestList.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *SECBnT) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the SE into 'w' in format defined in
// the document #575623.
func (s *SECBnT) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the SE.
func (s *SECBnT) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *SECBnT) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	base := s.Common.PrettyString(depth, withHeader, s, "IBB Segments Element", opts...)
	var lines []string
	lines = append(lines, base)

	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)), s.IBBSegments))
	for i := 0; i < len(s.IBBSegments); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.IBBSegments[i].PrettyString(depth+2, true)))
	}

	if depth < 1 {
		lines = append(lines, "")
	}
	if depth < 2 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// SE for BG
// PrettyString: IBB Segments Element
type SEBG struct {
	cbnt.Common
	cbnt.StructInfoBG `id:"__IBBS__" version:"0x10"`
	Reserved0         [1]byte   `require:"0" json:"seReserved0,omitempty"`
	Reserved1         [1]byte   `require:"0" json:"seReserved1,omitempty"`
	PBETValue         PBETValue `json:"sePBETValue"`
	Flags             SEFlags   `json:"seFlags"`
	// PrettyString: IBB MCHBAR
	IBBMCHBAR uint64 `json:"seIBBMCHBAR"`
	// PrettyString: VT-d BAR
	VTdBAR uint64 `json:"seVTdBAR"`
	// PrettyString: DMA Protection 0 Base Address
	PMRLBase uint32 `json:"seDMAProtBase0"`
	// PrettyString: DMA Protection 0 Limit Address
	PMRLLimit uint32 `json:"seDMAProtLimit0"`
	// PrettyString: DMA Protection 1 Base Address
	Reserved2 [8]byte `json:"seDMAProtBase1"`
	// PrettyString: DMA Protection 2 Limit Address
	Reserved3 [8]byte `json:"seDMAProtLimit1"`

	PostIBBHash cbnt.HashStructureFill `json:"sePostIBBHash"`

	IBBEntryPoint uint32 `json:"seIBBEntry"`

	Digest cbnt.HashStructure `json:"seDigestList"`

	IBBSegments []IBBSegment `countType:"uint8" json:"seIBBSegments,omitempty"`
}

func (s *SEBG) Layout() []cbnt.LayoutField {
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
			Name:  "Reserved 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    2,
			Name:  "Reserved 1",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved1 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    3,
			Name:  "PBET Value",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.PBETValue },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "Flags",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Flags },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "IBB MCHBAR",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.IBBMCHBAR },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "VT-d BAR",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.VTdBAR },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    7,
			Name:  "PMRL Base",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.PMRLBase },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    8,
			Name:  "PMRL Limit",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.PMRLLimit },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    9,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.Reserved2 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    10,
			Name:  "Reserved 3",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.Reserved3 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    11,
			Name:  "Post IBB Hash",
			Size:  func() uint64 { return s.PostIBBHash.TotalSize() },
			Value: func() any { return &s.PostIBBHash },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    12,
			Name:  "IBB Entry Point",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.IBBEntryPoint },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    13,
			Name:  "Digest",
			Size:  func() uint64 { return s.Digest.TotalSize() },
			Value: func() any { return &s.Digest },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   14,
			Name: fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint8(0)))
				for idx := range s.IBBSegments {
					size += s.IBBSegments[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.IBBSegments },
			Type:  cbnt.ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint8
				if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'IBBSegments': %w", err)
				}
				totalN := int64(binary.Size(count))
				s.IBBSegments = make([]IBBSegment, count)
				for idx := range s.IBBSegments {
					n, err := s.IBBSegments[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'IBBSegments[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
			WriteList: func(w io.Writer) (int64, error) {
				count := uint8(len(s.IBBSegments))
				if err := binary.Write(w, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to write the count for field 'IBBSegments': %w", err)
				}
				totalN := int64(binary.Size(count))
				for idx := range s.IBBSegments {
					n, err := s.IBBSegments[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'IBBSegments[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
		},
	}
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *SEBG) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoBG
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *SEBG) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoBG = newStructInfo.(cbnt.StructInfoBG)
}

// Has to be here to fullfil the reuirements of cbnt.Structure
func (s *SEBG) ReadFrom(r io.Reader) (int64, error) {
	return s.ReadFromHelper(r, true)
}

// ReadFrom reads the SE from 'r' in format defined in the document #575623.
func (s *SEBG) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// WriteTo writes the SE into 'w' in format defined in
// the document #575623.
func (s *SEBG) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s *SEBG) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("SE: %v", err)
	}

	return ret, nil
}

func (s *SEBG) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("SE: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the SE.
func (s *SEBG) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *SEBG) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	base := s.Common.PrettyString(depth, withHeader, s, "IBB Segments Element", opts...)
	var lines []string
	lines = append(lines, base)

	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)), s.IBBSegments))
	for i := 0; i < len(s.IBBSegments); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.IBBSegments[i].PrettyString(depth+2, true)))
	}

	if depth < 1 {
		lines = append(lines, "")
	}
	if depth < 2 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// CachingType <TO BE DOCUMENTED>
type CachingType uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v CachingType) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v CachingType) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the CachingType into 'w' in binary format.
func (v CachingType) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the CachingType from 'r' in binary format.
func (v CachingType) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PBETValue <TO BE DOCUMENTED>
type PBETValue uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (pbet PBETValue) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "PBET Value", pbet))
	}
	lines = append(lines, pretty.SubValue(depth+1, "PBET Value", "", pbet.PBETValue(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (pbet PBETValue) TotalSize() uint64 {
	return uint64(binary.Size(pbet))
}

// WriteTo writes the PBETValue into 'w' in binary format.
func (pbet PBETValue) WriteTo(w io.Writer) (int64, error) {
	return int64(pbet.TotalSize()), binary.Write(w, binary.LittleEndian, pbet)
}

// ReadFrom reads the PBETValue from 'r' in binary format.
func (pbet PBETValue) ReadFrom(r io.Reader) (int64, error) {
	return int64(pbet.TotalSize()), binary.Read(r, binary.LittleEndian, pbet)
}

// SEFlags <TO BE DOCUMENTED>
type SEFlags uint32

// PrettyString returns the bits of the flags in an easy-to-read format.
func (flags SEFlags) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "SE Flags", flags))
	}
	lines = append(lines, pretty.SubValue(depth+1, "Reserved 0", "", flags.Reserved0(), opts...)...)
	if flags.SupportsTopSwapRemediation() {
		lines = append(lines, pretty.SubValue(depth+1, "Supports Top Swap Remediation", "BIOS supports Top Swap remediation action", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Supports Top Swap Remediation", "BIOS does not support Top Swap remediation action", false, opts...)...)
	}
	if flags.TPMFailureLeavesHierarchiesEnabled() {
		lines = append(lines, pretty.SubValue(depth+1, "TPM Failure Leaves Hierarchies Enabled", "Leave Hierarchies enabled. Cap all PCRs on failure.", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "TPM Failure Leaves Hierarchies Enabled", "Do not leave enabled. Disable all Hierarchies or deactivate on failure.", false, opts...)...)
	}
	if flags.AuthorityMeasure() {
		lines = append(lines, pretty.SubValue(depth+1, "Authority Measure", "Extend Authority Measurements into the Authority PCR 7", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Authority Measure", "Do not extend into the Authority PCR 7", false, opts...)...)
	}
	if flags.Locality3Startup() {
		lines = append(lines, pretty.SubValue(depth+1, "Locality 3 Startup", "Issue TPM Start-up from Locality 3", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Locality 3 Startup", "Disabled", false, opts...)...)
	}
	if flags.DMAProtection() {
		lines = append(lines, pretty.SubValue(depth+1, "DMA Protection", "Enable DMA Protection", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "DMA Protection", "Disable DMA Protection", false, opts...)...)
	}
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (flags SEFlags) TotalSize() uint64 {
	return uint64(binary.Size(flags))
}

// WriteTo writes the SEFlags into 'w' in binary format.
func (flags SEFlags) WriteTo(w io.Writer) (int64, error) {
	return int64(flags.TotalSize()), binary.Write(w, binary.LittleEndian, flags)
}

// ReadFrom reads the SEFlags from 'r' in binary format.
func (flags SEFlags) ReadFrom(r io.Reader) (int64, error) {
	return int64(flags.TotalSize()), binary.Read(r, binary.LittleEndian, flags)
}

// PBETValue returns the raw value of the timer setting.
func (pbet PBETValue) PBETValue() uint8 {
	return uint8(pbet) & 0x0f
}

// Duration returns the value as time.Duration.
func (pbet PBETValue) Duration() time.Duration {
	v := pbet.PBETValue()
	if v == 0 {
		return math.MaxInt64
	}
	return time.Second * time.Duration(5+v)
}

// SetDuration sets the value using standard time.Duration as the input.
func (pbet *PBETValue) SetDuration(duration time.Duration) time.Duration {
	v := duration.Nanoseconds()/time.Second.Nanoseconds() - 5
	if v <= 0 {
		v = 1
	}
	if v >= 16 {
		v = 0
	}
	*pbet = PBETValue(v)

	return pbet.Duration()
}

// Reserved0 <TO BE DOCUMENTED>
func (flags SEFlags) Reserved0() uint32 {
	return uint32(flags & 0xffffffe0)
}

// SupportsTopSwapRemediation <TO BE DOCUMENTED>
//
// PrettyString-true:  BIOS supports Top Swap remediation action
// PrettyString-false: BIOS does not support Top Swap remediation action
func (flags SEFlags) SupportsTopSwapRemediation() bool {
	return flags&0x10 != 0
}

// TPMFailureLeavesHierarchiesEnabled <TO BE DOCUMENTED>
//
// PrettyString-true:  Leave Hierarchies enabled. Cap all PCRs on failure.
// PrettyString-false: Do not leave enabled. Disable all Hierarchies or deactivate on failure.
func (flags SEFlags) TPMFailureLeavesHierarchiesEnabled() bool {
	return flags&0x08 != 0
}

// AuthorityMeasure <TO BE DOCUMENTED>
//
// NOTE: PCR[7] is disabled from MTL onwards
//
// PrettyString-true:  Extend Authority Measurements into the Authority PCR 7
// PrettyString-false: Do not extend into the Authority PCR 7
func (flags SEFlags) AuthorityMeasure() bool {
	return flags&0x04 != 0
}

// Locality3Startup <TO BE DOCUMENTED>
//
// PrettyString-true:  Issue TPM Start-up from Locality 3
// PrettyString-false: Disabled
func (flags SEFlags) Locality3Startup() bool {
	return flags&0x02 != 0
}

// DMAProtection <TO BE DOCUMENTED>
//
// PrettyString-true:  Enable DMA Protection
// PrettyString-false: Disable DMA Protection
func (flags SEFlags) DMAProtection() bool {
	return flags&0x01 != 0
}

// String implements fmt.Stringer.
func (v CachingType) String() string {
	switch v {
	case CachingTypeWriteProtect:
		return "write_protect"
	case CachingTypeWriteBack:
		return "write_back"
	case CachingTypeReserved0:
		return "value_0x02"
	case CachingTypeReserved1:
		return "value_0x03"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(v))
}
