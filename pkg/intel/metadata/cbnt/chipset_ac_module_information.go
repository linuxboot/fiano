// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// See document 315168-017, A.1.2, Table 12, p.91
var chipsetACModuleInformationSignature = []byte{
	0xAA, 0x3A, 0xC0, 0x7F, 0xA7, 0x46, 0xDB, 0x18,
	0x2E, 0xAC, 0x69, 0x8F, 0x8D, 0x41, 0x7F, 0x5A,
}

// ChipsetACModuleInformation represents Chipset AC Module Information Table parts for all versions
type ChipsetACModuleInformation struct {
	Common
	UUID            [16]byte
	ChipsetACMType  uint8
	Version         uint8
	Length          uint16
	ChipsetIDList   uint32
	OsSinitDataVer  uint32
	MinMleHeaderVer uint32
	Capabilities    uint32
	AcmVersion      uint8
	AcmRevision     [3]uint8
	ProcessorIDList uint32
	TPMInfoList     uint32
}

// NewChipsetACModuleInformation returns a new instance of ChipsetACModuleInformation with
// all default values set.
func NewChipsetACModuleInformation() *ChipsetACModuleInformation {
	s := &ChipsetACModuleInformation{}
	return s
}

// ParseChipsetACModuleInformation parses Chipset AC Module Information Table according to the version
func ParseChipsetACModuleInformation(r io.Reader) (ChipsetACModuleInformation, error) {
	acm := NewChipsetACModuleInformation()
	_, err := acm.ReadFrom(r)
	if err != nil {
		return ChipsetACModuleInformation{}, err
	}

	if acm.Version >= 5 {
		if !bytes.Equal(acm.UUID[:], chipsetACModuleInformationSignature) {
			return ChipsetACModuleInformation{}, fmt.Errorf(
				"incorrect UUID [%x], expected: [%x]", acm.UUID, chipsetACModuleInformationSignature)
		}

		err = binary.Read(r, binary.LittleEndian, &acm.TPMInfoList)
		if err != nil {
			return ChipsetACModuleInformation{}, err
		}
	}

	return *acm, nil
}

// ReadFrom reads the ChipsetACModuleInformation from 'r' in format defined in the document #575623.
func (s *ChipsetACModuleInformation) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// WriteTo writes the ChipsetACModuleInformation into 'w' in format defined in
// the document #575623.
func (s *ChipsetACModuleInformation) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s *ChipsetACModuleInformation) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "UUID",
			Size:  func() uint64 { return 16 },
			Value: func() any { return &s.UUID },
			Type:  ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Chipset ACM Type",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.ChipsetACMType },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Length",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Length },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "Chipset ID List",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.ChipsetIDList },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Os Sinit Data Ver",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.OsSinitDataVer },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "Min Mle Header Ver",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.MinMleHeaderVer },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    7,
			Name:  "Capabilities",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Capabilities },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    8,
			Name:  "Acm Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.AcmVersion },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    9,
			Name:  "Acm Revision",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &s.AcmRevision },
			Type:  ManifestFieldArrayStatic,
		},
		{
			ID:    10,
			Name:  "Processor ID List",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.ProcessorIDList },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    11,
			Name:  "TPM Info List",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.TPMInfoList },
			Type:  ManifestFieldEndValue,
		},
	}
}

func (s *ChipsetACModuleInformation) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *ChipsetACModuleInformation) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *ChipsetACModuleInformation) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *ChipsetACModuleInformation) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Chipset AC Module Information", opts...)
}
