// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !manifestcodegen
// +build !manifestcodegen

// Code generated by "menifestcodegen". DO NOT EDIT.
// To reproduce: go run github.com/linuxboot/fiano/pkg/intel/metadata/common/manifestcodegen/cmd/manifestcodegen -package bg github.com/linuxboot/fiano/pkg/intel/metadata/bg

package bg

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

var (
	// Just to avoid errors in "import" above in case if it wasn't used below
	_ = binary.LittleEndian
	_ = (fmt.Stringer)(nil)
	_ = (io.Reader)(nil)
	_ = pretty.Header
	_ = strings.Join
)

// NewHashStructure returns a new instance of HashStructure with
// all default values set.
func NewHashStructure() *HashStructure {
	s := &HashStructure{}
	// Set through tag "default":
	s.HashAlg = 0x10
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *HashStructure) Validate() error {

	return nil
}

// ReadFrom reads the HashStructure from 'r' in format defined in the document #575623.
func (s *HashStructure) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// HashBuffer (ManifestFieldType: arrayDynamic)
	{
		var size uint16
		err := binary.Read(r, binary.LittleEndian, &size)
		if err != nil {
			return totalN, fmt.Errorf("unable to the read size of field 'HashBuffer': %w", err)
		}
		totalN += int64(binary.Size(size))
		s.HashBuffer = make([]byte, size)
		n, err := len(s.HashBuffer), binary.Read(r, binary.LittleEndian, s.HashBuffer)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'HashBuffer': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *HashStructure) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *HashStructure) Rehash() {
}

// WriteTo writes the HashStructure into 'w' in format defined in
// the document #575623.
func (s *HashStructure) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// HashBuffer (ManifestFieldType: arrayDynamic)
	{
		size := uint16(len(s.HashBuffer))
		err := binary.Write(w, binary.LittleEndian, size)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the size of field 'HashBuffer': %w", err)
		}
		totalN += int64(binary.Size(size))
		n, err := len(s.HashBuffer), binary.Write(w, binary.LittleEndian, s.HashBuffer)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashBuffer': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// HashAlgSize returns the size in bytes of the value of field HashAlg
func (s *HashStructure) HashAlgTotalSize() uint64 {
	return 2
}

// HashBufferSize returns the size in bytes of the value of field HashBuffer
func (s *HashStructure) HashBufferTotalSize() uint64 {
	size := uint64(binary.Size(uint16(0)))
	size += uint64(len(s.HashBuffer))
	return size
}

// HashAlgOffset returns the offset in bytes of field HashAlg
func (s *HashStructure) HashAlgOffset() uint64 {
	return 0
}

// HashBufferOffset returns the offset in bytes of field HashBuffer
func (s *HashStructure) HashBufferOffset() uint64 {
	return s.HashAlgOffset() + s.HashAlgTotalSize()
}

// Size returns the total size of the HashStructure.
func (s *HashStructure) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.HashAlgTotalSize()
	size += s.HashBufferTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashStructure) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Hash Structure", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Hash Alg", "", &s.HashAlg, opts...)...)
	// ManifestFieldType is arrayDynamic
	lines = append(lines, pretty.SubValue(depth+1, "Hash Buffer", "", &s.HashBuffer, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// NewHashStructureFill returns a new instance of HashStructureFill with
// all default values set.
func NewHashStructureFill() *HashStructureFill {
	s := &HashStructureFill{}
	// Set through tag "default":
	s.HashAlg = 0x0b
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *HashStructureFill) Validate() error {

	return nil
}

// ReadFrom reads the HashStructureFill from 'r' in format defined in the document #575623.
func (s *HashStructureFill) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// HashBuffer (ManifestFieldType: arrayDynamic)
	{
		size := uint16(s.hashSize())
		s.HashBuffer = make([]byte, size)
		n, err := len(s.HashBuffer), binary.Read(r, binary.LittleEndian, s.HashBuffer)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'HashBuffer': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *HashStructureFill) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *HashStructureFill) Rehash() {
}

// WriteTo writes the HashStructureFill into 'w' in format defined in
// the document #575623.
func (s *HashStructureFill) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// HashBuffer (ManifestFieldType: arrayDynamic)
	{
		n, err := len(s.HashBuffer), binary.Write(w, binary.LittleEndian, s.HashBuffer)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashBuffer': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// HashAlgSize returns the size in bytes of the value of field HashAlg
func (s *HashStructureFill) HashAlgTotalSize() uint64 {
	return 2
}

// HashBufferSize returns the size in bytes of the value of field HashBuffer
func (s *HashStructureFill) HashBufferTotalSize() uint64 {
	return uint64(len(s.HashBuffer))
}

// HashAlgOffset returns the offset in bytes of field HashAlg
func (s *HashStructureFill) HashAlgOffset() uint64 {
	return 0
}

// HashBufferOffset returns the offset in bytes of field HashBuffer
func (s *HashStructureFill) HashBufferOffset() uint64 {
	return s.HashAlgOffset() + s.HashAlgTotalSize()
}

// Size returns the total size of the HashStructureFill.
func (s *HashStructureFill) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.HashAlgTotalSize()
	size += s.HashBufferTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashStructureFill) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Hash Structure Fill", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Hash Alg", "", &s.HashAlg, opts...)...)
	// ManifestFieldType is arrayDynamic
	lines = append(lines, pretty.SubValue(depth+1, "Hash Buffer", "", s.hashSizePrint(), opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
