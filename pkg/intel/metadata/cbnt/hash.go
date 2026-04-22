// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// HashList describes multiple digests
type HashList struct {
	Common
	Size uint16          `rehashValue:"TotalSize()" json:"hlSize"`
	List []HashStructure `json:"hlList"`
}

// NewHashList returns a new instance of HashList with
// all default values set.
func NewHashList() *HashList {
	s := &HashList{}
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *HashList) Validate() error {
	expectedValue := uint16(s.Common.TotalSize(s))
	if s.Size != expectedValue {
		return fmt.Errorf("field 'Size' expects write-value '%v', but has %v", expectedValue, s.Size)
	}

	return nil
}

// ReadFrom reads the HashList from 'r' in format defined in the document #575623.
func (s *HashList) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *HashList) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *HashList) Rehash() {
	s.Size = uint16(s.Common.TotalSize(s))
}

// WriteTo writes the HashList into 'w' in format defined in
// the document #575623.
func (s *HashList) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

func (s *HashList) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Size },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:   1,
			Name: fmt.Sprintf("List: Array of \"Hash List\" of length %d", len(s.List)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				for idx := range s.List {
					size += s.List[idx].Common.TotalSize(&s.List[idx])
				}
				return size
			},
			Value: func() any { return &s.List },
			Type:  ManifestFieldList,
			// this is basically the logic from ReadFrom of HashList
			// for the ManifestFieldType list. Just that now we pass it
			// as closure and let generic ReadFrom make use of it.
			ReadList: func(r io.Reader) (int64, error) {
				var count uint16
				if err := binary.Read(r, endianess, &count); err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'List': %w", err)
				}
				totalN := int64(binary.Size(count))

				s.List = make([]HashStructure, count)
				for idx := range s.List {
					n, err := s.List[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'List[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
			WriteList: func(w io.Writer) (int64, error) {
				count := uint16(len(s.List))
				if err := binary.Write(w, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to write the count for field 'List': %w", err)
				}
				totalN := int64(binary.Size(count))

				for idx := range s.List {
					n, err := s.List[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'List[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}

				return totalN, nil
			},
		},
	}
}

func (s *HashList) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		// normally it would be 0, but ret is already 0 if we land here
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *HashList) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the HashList.
func (s *HashList) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashList) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	base := Common{}.PrettyString(depth, withHeader, s, "Hash List", opts...)
	var lines []string
	lines = append(lines, base)

	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("List: Array of \"Hash List\" of length %d", len(s.List)), s.List))
	for i := 0; i < len(s.List); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.List[i].PrettyString(depth+2, true, opts...)))
	}

	if depth < 1 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

type HashStructure struct {
	Common
	HashAlg    Algorithm `default:"0x10" json:"hsAlg"`
	HashBuffer []byte    `json:"hsBuffer"`
}

// NewHashStructure returns a new instance of HashStructure with
// all default values set.
func NewHashStructure(alg Algorithm) *HashStructure {
	s := &HashStructure{}
	// For bg pkg, the default one
	s.HashAlg = alg
	return s
}

// ReadFrom reads the HashStructure from 'r' in format defined in the document #575623.
func (s *HashStructure) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// WriteTo writes the HashStructure into 'w' in format defined in
// the document #575623.
func (s *HashStructure) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s *HashStructure) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.HashAlg },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:   1,
			Name: "Hash Buffer",
			Size: func() uint64 {
				h, err := s.HashAlg.Hash()
				if err != nil {
					return uint64(binary.Size(uint16(0)))
				}
				return uint64(binary.Size(uint16(0))) + uint64(h.Size())
			},
			Value: func() any { return &s.HashBuffer },
			Type:  ManifestFieldArrayDynamicWithPrefix,
		},
	}
}

func (s *HashStructure) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		// normally it would be 0, but ret is already 0 if we land here
		return ret, fmt.Errorf("HashStructure: %v", err)
	}

	return ret, nil
}

func (s *HashStructure) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashStructure: %v", err)
	}

	return ret, nil
}

func (s *HashStructure) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashStructure) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Hash Structure", opts...)
}

// HashStructureFill describes a digest in BG fill format.
// Unlike HashStructure, HashBuffer does not carry a size prefix on the wire.
type HashStructureFill struct {
	Common
	HashAlg    Algorithm `default:"0x0b" json:"hsAlg"`
	HashBuffer []byte    `json:"hsBuffer"`
}

// NewHashStructureFill returns a new instance of HashStructureFill with
// all default values set. Note: here only for legacy reasons (i.e. supporting
// BG 1.0).
func NewHashStructureFill(alg Algorithm) *HashStructureFill {
	s := &HashStructureFill{}
	s.HashAlg = alg
	return s
}

// this little hack here mimics the hack from old bg package
func (s *HashStructureFill) hashBufferSize() uint64 {
	const hashSizeFieldLen = 2
	if s.HashAlg.IsNull() {
		return 32 + hashSizeFieldLen
	}

	h, err := s.HashAlg.Hash()
	if err != nil {
		return hashSizeFieldLen
	}
	return uint64((h.Size() + hashSizeFieldLen))
}

// ReadFrom reads the HashStructureFill from 'r' in format defined in the document #575623.
func (s *HashStructureFill) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// WriteTo writes the HashStructureFill into 'w' in format defined in
// the document #575623.
func (s *HashStructureFill) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s *HashStructureFill) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.HashAlg },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    1,
			Name:  "Hash Buffer",
			Size:  s.hashBufferSize,
			Value: func() any { return &s.HashBuffer },
			Type:  ManifestFieldArrayDynamicWithSize,
		},
	}
}

func (s *HashStructureFill) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashStructureFill: %v", err)
	}

	return ret, nil
}

func (s *HashStructureFill) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashStructureFill: %v", err)
	}

	return ret, nil
}

func (s *HashStructureFill) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashStructureFill) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Hash Structure Fill", opts...)
}
