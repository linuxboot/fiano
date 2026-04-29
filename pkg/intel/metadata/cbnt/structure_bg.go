// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type StructInfoBG struct {
	Common
	ID      StructureID `json:"StructInfoID"`
	Version uint8       `json:"StructInfoVersion"`
}

// ReadFrom reads the StructInfo from 'r' in format defined in the document #575623.
func (s StructInfoBG) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// Validate (recursively) checks the structure if there are any unexpected values.
func (s StructInfoBG) Validate() error {
	// dummy
	return nil
}

// WriteTo writes the StructInfo into 'w' in format defined in
// the document #575623.
func (s StructInfoBG) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

// Layout returns the structure's layout descriptor
func (s StructInfoBG) Layout() []LayoutField {
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
	}
}

// SizeOf returns the size of the structure's field of a given id.
func (s StructInfoBG) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// OffsetOf returns the offset of the structure's field of a given id.
func (s StructInfoBG) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the StructInfo.
func (s StructInfoBG) TotalSize() uint64 {
	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s StructInfoBG) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Struct Info", opts...)
}

// StructInfo just returns StructInfo, it is a handy method if StructInfo
// is included anonymously to another type.
func (s StructInfoBG) StructInfo() StructInfo {
	return s
}
