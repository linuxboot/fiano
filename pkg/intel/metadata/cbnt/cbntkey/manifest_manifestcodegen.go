// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !manifestcodegen
// +build !manifestcodegen

// Code generated by "menifestcodegen". DO NOT EDIT.
// To reproduce: go run github.com/linuxboot/fiano/pkg/intel/metadata/common/manifestcodegen/cmd/manifestcodegen github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/cbntkey

package cbntkey

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
	_ = cbnt.StructInfo{}
)

// NewManifest returns a new instance of Manifest with
// all default values set.
func NewManifest() *Manifest {
	s := &Manifest{}
	copy(s.StructInfo.ID[:], []byte(StructureIDManifest))
	s.StructInfo.Version = 0x21
	// Recursively initializing a child structure:
	s.KeyAndSignature = *cbnt.NewKeySignature()
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Manifest) Validate() error {
	// See tag "rehashValue"
	{
		expectedValue := uint16(s.KeyAndSignatureOffset())
		if s.KeyManifestSignatureOffset != expectedValue {
			return fmt.Errorf("field 'KeyManifestSignatureOffset' expects write-value '%v', but has %v", expectedValue, s.KeyManifestSignatureOffset)
		}
	}
	// Recursively validating a child structure:
	if err := s.KeyAndSignature.Validate(); err != nil {
		return fmt.Errorf("error on field 'KeyAndSignature': %w", err)
	}

	return nil
}

// StructureIDManifest is the StructureID (in terms of
// the document #575623) of element 'Manifest'.
const StructureIDManifest = "__KEYM__"

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Manifest) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Manifest) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (s *Manifest) ReadFrom(r io.Reader) (int64, error) {
	var totalN int64

	err := binary.Read(r, binary.LittleEndian, &s.StructInfo)
	if err != nil {
		return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
	}
	totalN += int64(binary.Size(s.StructInfo))

	n, err := s.ReadDataFrom(r)
	if err != nil {
		return totalN, fmt.Errorf("unable to read data: %w", err)
	}
	totalN += n

	return totalN, nil
}

// ReadDataFrom reads the Manifest from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *Manifest) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// KeyManifestSignatureOffset (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.KeyManifestSignatureOffset)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeyManifestSignatureOffset': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved2 (ManifestFieldType: arrayStatic)
	{
		n, err := 3, binary.Read(r, binary.LittleEndian, s.Reserved2[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Reserved2': %w", err)
		}
		totalN += int64(n)
	}

	// Revision (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.Revision)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Revision': %w", err)
		}
		totalN += int64(n)
	}

	// KMSVN (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMSVN)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMSVN': %w", err)
		}
		totalN += int64(n)
	}

	// KMID (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMID)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMID': %w", err)
		}
		totalN += int64(n)
	}

	// PubKeyHashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.PubKeyHashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'PubKeyHashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Hash (ManifestFieldType: list)
	{
		var count uint16
		err := binary.Read(r, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to read the count for field 'Hash': %w", err)
		}
		totalN += int64(binary.Size(count))
		s.Hash = make([]Hash, count)

		for idx := range s.Hash {
			n, err := s.Hash[idx].ReadFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field 'Hash[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	// KeyAndSignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeyAndSignature.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeyAndSignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Manifest) RehashRecursive() {
	s.StructInfo.Rehash()
	s.KeyAndSignature.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Manifest) Rehash() {
	s.Variable0 = 0
	s.ElementSize = 0
	s.KeyManifestSignatureOffset = uint16(s.KeyAndSignatureOffset())
}

// WriteTo writes the Manifest into 'w' in format defined in
// the document #575623.
func (s *Manifest) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// StructInfo (ManifestFieldType: structInfo)
	{
		n, err := s.StructInfo.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'StructInfo': %w", err)
		}
		totalN += int64(n)
	}

	// KeyManifestSignatureOffset (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeyManifestSignatureOffset)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyManifestSignatureOffset': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved2 (ManifestFieldType: arrayStatic)
	{
		n, err := 3, binary.Write(w, binary.LittleEndian, s.Reserved2[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved2': %w", err)
		}
		totalN += int64(n)
	}

	// Revision (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.Revision)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Revision': %w", err)
		}
		totalN += int64(n)
	}

	// KMSVN (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.KMSVN)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KMSVN': %w", err)
		}
		totalN += int64(n)
	}

	// KMID (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.KMID)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KMID': %w", err)
		}
		totalN += int64(n)
	}

	// PubKeyHashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.PubKeyHashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PubKeyHashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Hash (ManifestFieldType: list)
	{
		count := uint16(len(s.Hash))
		err := binary.Write(w, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the count for field 'Hash': %w", err)
		}
		totalN += int64(binary.Size(count))
		for idx := range s.Hash {
			n, err := s.Hash[idx].WriteTo(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'Hash[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	// KeyAndSignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeyAndSignature.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyAndSignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// StructInfoSize returns the size in bytes of the value of field StructInfo
func (s *Manifest) StructInfoTotalSize() uint64 {
	return s.StructInfo.TotalSize()
}

// KeyManifestSignatureOffsetSize returns the size in bytes of the value of field KeyManifestSignatureOffset
func (s *Manifest) KeyManifestSignatureOffsetTotalSize() uint64 {
	return 2
}

// Reserved2Size returns the size in bytes of the value of field Reserved2
func (s *Manifest) Reserved2TotalSize() uint64 {
	return 3
}

// RevisionSize returns the size in bytes of the value of field Revision
func (s *Manifest) RevisionTotalSize() uint64 {
	return 1
}

// KMSVNSize returns the size in bytes of the value of field KMSVN
func (s *Manifest) KMSVNTotalSize() uint64 {
	return 1
}

// KMIDSize returns the size in bytes of the value of field KMID
func (s *Manifest) KMIDTotalSize() uint64 {
	return 1
}

// PubKeyHashAlgSize returns the size in bytes of the value of field PubKeyHashAlg
func (s *Manifest) PubKeyHashAlgTotalSize() uint64 {
	return 2
}

// HashSize returns the size in bytes of the value of field Hash
func (s *Manifest) HashTotalSize() uint64 {
	var size uint64
	size += uint64(binary.Size(uint16(0)))
	for idx := range s.Hash {
		size += s.Hash[idx].TotalSize()
	}
	return size
}

// KeyAndSignatureSize returns the size in bytes of the value of field KeyAndSignature
func (s *Manifest) KeyAndSignatureTotalSize() uint64 {
	return s.KeyAndSignature.TotalSize()
}

// StructInfoOffset returns the offset in bytes of field StructInfo
func (s *Manifest) StructInfoOffset() uint64 {
	return 0
}

// KeyManifestSignatureOffsetOffset returns the offset in bytes of field KeyManifestSignatureOffset
func (s *Manifest) KeyManifestSignatureOffsetOffset() uint64 {
	return s.StructInfoOffset() + s.StructInfoTotalSize()
}

// Reserved2Offset returns the offset in bytes of field Reserved2
func (s *Manifest) Reserved2Offset() uint64 {
	return s.KeyManifestSignatureOffsetOffset() + s.KeyManifestSignatureOffsetTotalSize()
}

// RevisionOffset returns the offset in bytes of field Revision
func (s *Manifest) RevisionOffset() uint64 {
	return s.Reserved2Offset() + s.Reserved2TotalSize()
}

// KMSVNOffset returns the offset in bytes of field KMSVN
func (s *Manifest) KMSVNOffset() uint64 {
	return s.RevisionOffset() + s.RevisionTotalSize()
}

// KMIDOffset returns the offset in bytes of field KMID
func (s *Manifest) KMIDOffset() uint64 {
	return s.KMSVNOffset() + s.KMSVNTotalSize()
}

// PubKeyHashAlgOffset returns the offset in bytes of field PubKeyHashAlg
func (s *Manifest) PubKeyHashAlgOffset() uint64 {
	return s.KMIDOffset() + s.KMIDTotalSize()
}

// HashOffset returns the offset in bytes of field Hash
func (s *Manifest) HashOffset() uint64 {
	return s.PubKeyHashAlgOffset() + s.PubKeyHashAlgTotalSize()
}

// KeyAndSignatureOffset returns the offset in bytes of field KeyAndSignature
func (s *Manifest) KeyAndSignatureOffset() uint64 {
	return s.HashOffset() + s.HashTotalSize()
}

// Size returns the total size of the Manifest.
func (s *Manifest) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.StructInfoTotalSize()
	size += s.KeyManifestSignatureOffsetTotalSize()
	size += s.Reserved2TotalSize()
	size += s.RevisionTotalSize()
	size += s.KMSVNTotalSize()
	size += s.KMIDTotalSize()
	size += s.PubKeyHashAlgTotalSize()
	size += s.HashTotalSize()
	size += s.KeyAndSignatureTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Manifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "CBnT Key Manifest", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is structInfo
	lines = append(lines, pretty.SubValue(depth+1, "Struct Info", "", &s.StructInfo, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Key Manifest Signature Offset", "", &s.KeyManifestSignatureOffset, opts...)...)
	// ManifestFieldType is arrayStatic
	lines = append(lines, pretty.SubValue(depth+1, "Reserved 2", "", &s.Reserved2, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Revision", "", &s.Revision, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "KMSVN", "", &s.KMSVN, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "KMID", "", &s.KMID, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Pub Key Hash Alg", "", &s.PubKeyHashAlg, opts...)...)
	// ManifestFieldType is list
	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("Hash: Array of \"Key Manifest\" of length %d", len(s.Hash)), s.Hash))
	for i := 0; i < len(s.Hash); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.Hash[i].PrettyString(depth+2, true)))
	}
	if depth < 1 {
		lines = append(lines, "")
	}
	// ManifestFieldType is subStruct
	lines = append(lines, pretty.SubValue(depth+1, "Key And Signature", "", &s.KeyAndSignature, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
