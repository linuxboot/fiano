// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// StructureID is the magic ID string used to identify the structure type
// in the manifest
type StructureID [8]byte

type StructInfoCBNT struct {
	Common
	ID          StructureID `json:"StructInfoID"`
	Version     uint8       `json:"StructInfoVersion"`
	Variable0   uint8       `json:"StructInfoVariable0"`
	ElementSize uint16      `json:"StructInfoElementSize"`
}

// ReadFrom reads the StructInfo from 'r' in format defined in the document #575623.
func (s StructInfoCBNT) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

func (s StructInfoCBNT) Validate() error {
	// ID, version and element size might differ, only thing that we can always validate is
	// Variable0.
	if s.Variable0 != 0 {
		return fmt.Errorf("field 'Variable0' expects value '0', but has %v", s.Variable0)
	}
	return nil
}

// WriteTo writes the StructInfo into 'w' in format defined in
// the document #575623.
func (s StructInfoCBNT) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s StructInfoCBNT) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "ID",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.ID },
			Type:  ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Variable 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Variable0 },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Element Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.ElementSize },
			Type:  ManifestFieldEndValue,
		},
	}
}

func (s StructInfoCBNT) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("StructInfoCBnT: %v", err)
	}

	return ret, nil
}

func (s StructInfoCBNT) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("StructInfoCBnT: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the StructInfo.
func (s StructInfoCBNT) TotalSize() uint64 {
	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s StructInfoCBNT) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Struct Info", opts...)
}

// StructInfo just returns StructInfo, it is a handy method if StructInfo
// is included anonymously to another type.
func (s StructInfoCBNT) StructInfo() StructInfo {
	return s
}

// String returns the ID as a string.
func (s StructureID) String() string {
	return string(s[:])
}
