// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package key

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

const (
	StructureIDManifest = "__KEYM__"
	KMUnsignedSize      = 48
)

type Manifest struct {
	bg.StructInfo
	KMVersion       uint8            `json:"kmVersion"`
	KMSVN           bg.SVN           `json:"kmSVN"`
	KMID            uint8            `json:"kmID"`
	BPKey           bg.HashStructure `json:"kmBPKey"`
	KeyAndSignature bg.KeySignature  `json:"kmKeySignature"`
}

func NewManifest() *Manifest {
	m := &Manifest{}
	copy(m.StructInfo.ID[:], []byte(StructureIDManifest))
	m.StructInfo.Version = 0x10
	m.KeyAndSignature = *bg.NewKeySignature()
	return m
}

func (m *Manifest) SetSignature(
	algo bg.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Manifest) GetStructInfo() bg.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Manifest) SetStructInfo(newStructInfo bg.StructInfo) {
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

	// KMVersion (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMVersion)
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

	// Hash (ManifestFieldType: list)
	{
		n, err := s.BPKey.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read the count for field 'Hash': %w", err)
		}
		totalN += int64(n)
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

// Print prints the Key Manifest.
func (m *Manifest) Print() {
	if m.KeyAndSignature.Signature.DataTotalSize() < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Manifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Key Manifest", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is structInfo
	lines = append(lines, pretty.SubValue(depth+1, "Struct Info", "", &s.StructInfo, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Version", "", &s.KMVersion, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "KMSVN", "", &s.KMSVN, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "KMID", "", &s.KMID, opts...)...)
	// ManifestFieldType is subStruct
	lines = append(lines, pretty.SubValue(depth+1, "BPKEY:", "", &s.BPKey, opts...)...)
	// ManifestFieldType is subStruct
	lines = append(lines, pretty.SubValue(depth+1, "Key And Signature", "", &s.KeyAndSignature, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
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
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.KMVersion)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyManifestSignatureOffset': %w", err)
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

	// BPKey (ManifestFieldType: subStruct)
	{
		n, err := s.BPKey.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyAndSignature': %w", err)
		}
		totalN += int64(n)
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
