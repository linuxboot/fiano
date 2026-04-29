// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntkey

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type BGManifest struct {
	cbnt.Common
	cbnt.StructInfoBG `id:"__KEYM__" version:"0x10"`
	KMVersion         uint8              `json:"kmVersion"`
	KMSVN             cbnt.SVN           `json:"kmSVN"`
	KMID              uint8              `json:"kmID"`
	BPKey             cbnt.HashStructure `json:"kmBPKey"`
	KeyAndSignature   cbnt.KeySignature  `json:"kmKeySignature"`
}

// Setter for the Key signature.
func (m *BGManifest) SetSignature(
	algo cbnt.Algorithm,
	hashAlgo cbnt.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, algo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}

// ValidateBPMKey returns an error if BPKey does not match Key Signature from BPM.
func (m *BGManifest) ValidateBPMKey(bpmKS cbnt.KeySignature) error {
	h, err := m.BPKey.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash algo %v: %w", m.BPKey.HashAlg, err)
	}

	if len(m.BPKey.HashBuffer) != h.Size() {
		return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(m.BPKey.HashBuffer), h.Size())
	}

	switch bpmKS.Key.KeyAlg {
	case cbnt.AlgRSA:
		if _, err := h.Write(bpmKS.Key.Data[4:]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key algorithm: %v", bpmKS.Key.KeyAlg)
	}
	digest := h.Sum(nil)

	if !bytes.Equal(m.BPKey.HashBuffer, digest) {
		return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, m.BPKey.HashBuffer, m.BPKey.HashAlg)
	}

	return nil
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (m *BGManifest) Validate() error {
	// Recursively validating a child structure:
	if err := m.KeyAndSignature.Validate(); err != nil {
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
func (m *BGManifest) GetStructInfo() cbnt.StructInfo {
	return m.StructInfoBG
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (m *BGManifest) SetStructInfo(newStructInfo cbnt.StructInfo) {
	m.StructInfoBG = newStructInfo.(cbnt.StructInfoBG)
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (m *BGManifest) ReadFrom(r io.Reader) (int64, error) {
	return m.Common.ReadFrom(r, m)
}

// WriteTo writes the Manifest into 'w' in format defined in
// the document #575623.
func (m *BGManifest) WriteTo(w io.Writer) (int64, error) {
	return m.Common.WriteTo(w, m)
}

// Layout returns the structure's layout descriptor
func (m *BGManifest) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return m.StructInfoBG.TotalSize() },
			Value: func() any { return m.StructInfoBG },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "KM Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &m.KMVersion },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "KMSVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &m.KMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "KMID",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &m.KMID },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "BP Key",
			Size:  func() uint64 { return m.BPKey.TotalSize() },
			Value: func() any { return &m.BPKey },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    5,
			Name:  "Key And Signature",
			Size:  func() uint64 { return m.KeyAndSignature.TotalSize() },
			Value: func() any { return &m.KeyAndSignature },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

// SizeOf returns the size of the structure's field of a given id.
func (m *BGManifest) SizeOf(id int) (uint64, error) {
	ret, err := m.Common.SizeOf(m, id)
	if err != nil {
		return ret, fmt.Errorf("CBnTManifest: %v", err)
	}

	return ret, nil
}

// OffsetOf returns the offset of the structure's field of a given id.
func (m *BGManifest) OffsetOf(id int) (uint64, error) {
	ret, err := m.Common.OffsetOf(m, id)
	if err != nil {
		return ret, fmt.Errorf("CBnTManifest: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the Manifest.
func (m *BGManifest) TotalSize() uint64 {
	if m == nil {
		return 0
	}

	return m.Common.TotalSize(m)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (m *BGManifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return m.Common.PrettyString(depth, withHeader, m, "BG Key Manifest", opts...)
}

// Print prints the Key Manifest
func (m *BGManifest) Print() {
	if len(m.KeyAndSignature.Signature.Data) < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
