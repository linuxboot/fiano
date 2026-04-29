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

type Signature struct {
	cbnt.Common
	cbnt.StructInfo   `id:"__PMSG__" version:"0x20"`
	cbnt.KeySignature `json:"sigKeySignature"`
}

// NewSignature returns a new instance of Signature with
// all default values set.
func NewSignature(bgv cbnt.BootGuardVersion) (*Signature, error) {
	switch bgv {
	case cbnt.Version10:
		s := &Signature{StructInfo: cbnt.NewStructInfo(bgv)}
		copy(s.StructInfo.(*cbnt.StructInfoBG).ID[:], []byte(StructureIDSignature))
		s.StructInfo.(*cbnt.StructInfoBG).Version = 0x10
		// Recursively initializing a child structure:
		s.KeySignature = *cbnt.NewKeySignature()
		return s, nil
	case cbnt.Version20, cbnt.Version21:
		s := &Signature{StructInfo: cbnt.NewStructInfo(bgv)}
		copy(s.StructInfo.(*cbnt.StructInfoCBNT).ID[:], []byte(StructureIDSignature))
		s.StructInfo.(*cbnt.StructInfoCBNT).Version = 0x20
		s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize = 0
		s.StructInfo.(*cbnt.StructInfoCBNT).Variable0 = 0
		// Recursively initializing a child structure:
		s.KeySignature = *cbnt.NewKeySignature()
		return s, nil
	default:
		return nil, fmt.Errorf("version not supported")
	}
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Signature) Validate() error {
	// Recursively validating a child structure:
	if err := s.KeySignature.Validate(); err != nil {
		return fmt.Errorf("error on field 'KeySignature': %w", err)
	}

	return nil
}

// Layout returns the structure's layout descriptor
func (s *Signature) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfo.TotalSize() },
			Value: func() any { return s.StructInfo },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "Key Signature",
			Size:  func() uint64 { return s.KeySignature.TotalSize() },
			Value: func() any { return &s.KeySignature },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

// SizeOf returns the size of the structure's field of a given id.
func (s *Signature) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Signature: %v", err)
	}

	return ret, nil
}

// OffsetOf returns the offset of the structure's field of a given id.
func (s *Signature) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Signature: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Signature) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Signature) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// Dummy helper to satisfy cbnt.Structure Interface
func (s *Signature) ReadFrom(r io.Reader, info bool) (int64, error) {
	return s.ReadFromHelper(r, info)
}

// ReadFrom reads the Signature from 'r' in format defined in the document #575623.
func (s *Signature) ReadFromHelper(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})
}

// WriteTo writes the Signature into 'w' in format defined in
// the document #575623.
func (s *Signature) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

// Size returns the total size of the Signature.
func (s *Signature) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Signature) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "Signature", opts...)
}
