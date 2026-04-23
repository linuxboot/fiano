// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntkey

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// PrettyString: CBnT Key Manifest
type CBnTManifest struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__KEYM__" version:"0x21" var0:"0" var1:"0"`

	// KeyManifestSignatureOffset is Key Manifest KeySignature offset.
	//
	// The original name is "KeySignatureOffset" (in #575623).
	KeyManifestSignatureOffset uint16 `rehashValue:"KeyAndSignatureOffset()" json:"kmSigOffset,omitempty"`

	// Reserved2 is an alignment.
	Reserved2 [3]byte `json:"kmReserved2,omitempty"`

	// Revision is the revision of the Key Manifest defined by the Platform
	// Manufacturer.
	Revision uint8 `json:"kmRevision"`

	// KMSVN is the Key Manifest Security Version Number.
	KMSVN cbnt.SVN `json:"kmSVN"`

	// KMID is the Key Manifest Identifier.
	KMID uint8 `json:"kmID"`

	// PubKeyHashAlg is the hash algorithm of OEM public key digest programmed
	// into the FPF.
	PubKeyHashAlg cbnt.Algorithm `json:"kmPubKeyHashAlg"`

	// Hash is the slice of KMHASH_STRUCT (KHS) structures (see table 5-3
	// of the document #575623). Describes BPM pubkey digest (among other).
	Hash HashList `json:"kmHash"`

	// KeyAndSignature is the Key Manifest signature.
	KeyAndSignature cbnt.KeySignature `json:"kmKeySignature"`
}

type HashList []Hash

func (l *HashList) Structures() []cbnt.Structure {
	out := make([]cbnt.Structure, 0, len(*l))
	for i := range *l {
		out = append(out, &(*l)[i])
	}
	return out
}

func (m *CBnTManifest) SetSignature(
	algo cbnt.Algorithm,
	hashAlgo cbnt.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, hashAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}
	m.PubKeyHashAlg = m.KeyAndSignature.Signature.HashAlg

	return nil
}

func (m *CBnTManifest) ValidateBPMKey(bpmKS cbnt.KeySignature) error {
	hashCount := 0
	for _, hashEntry := range m.Hash {
		if !hashEntry.Usage.IsSet(UsageBPMSigningPKD) {
			continue
		}

		h, err := hashEntry.Digest.HashAlg.Hash()
		if err != nil {
			return fmt.Errorf("invalid hash algo %v: %w", hashEntry.Digest.HashAlg, err)
		}

		if len(hashEntry.Digest.HashBuffer) != h.Size() {
			return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(hashEntry.Digest.HashBuffer), h.Size())
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

		if !bytes.Equal(hashEntry.Digest.HashBuffer, digest) {
			return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, hashEntry.Digest.HashBuffer, hashEntry.Digest.HashAlg)
		}
		hashCount++
	}

	if hashCount == 0 {
		return fmt.Errorf("no hash of BPM's key was found in KM")
	}

	return nil
}

func (m *CBnTManifest) Validate() error {
	v, err := m.OffsetOf(8)
	if err != nil {
		return fmt.Errorf("error on field 'KeyAndSignature': %w", err)
	}
	expectedValue := uint16(v)
	if m.KeyManifestSignatureOffset != expectedValue {
		return fmt.Errorf("field 'KeyManifestSignatureOffset' expects write-value '%v', but has %v", expectedValue, m.KeyManifestSignatureOffset)
	}
	// Recursively validating a child structure:
	if err := m.KeyAndSignature.Validate(); err != nil {
		return fmt.Errorf("error on field 'KeyAndSignature': %w", err)
	}

	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (m *CBnTManifest) GetStructInfo() cbnt.StructInfo {
	return m.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (m *CBnTManifest) SetStructInfo(newStructInfo cbnt.StructInfo) {
	m.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (m *CBnTManifest) ReadFrom(r io.Reader) (int64, error) {
	return m.Common.ReadFrom(r, m)
}

// RehashRecursive calls Rehash (see below) recursively.
func (m *CBnTManifest) RehashRecursive() {
	m.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (m *CBnTManifest) Rehash() {
	m.Variable0 = 0
	m.ElementSize = 0
	v, err := m.OffsetOf(8)
	if err != nil {
		// TODO: this will never be true, but still lets think of how to handle
		fmt.Println("offset fail (todo handle better)")
	}
	m.KeyManifestSignatureOffset = uint16(v)
}

// WriteTo writes the Manifest into 'w' in format defined in
// the document #575623.
func (m *CBnTManifest) WriteTo(w io.Writer) (int64, error) {
	m.Rehash()
	return m.Common.WriteTo(w, m)
}

func (m *CBnTManifest) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return m.StructInfoCBNT.TotalSize() },
			Value: func() any { return m.StructInfoCBNT },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "Key Manifest Signature Offset",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &m.KeyManifestSignatureOffset },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &m.Reserved2 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    3,
			Name:  "Revision",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &m.Revision },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "KMSVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &m.KMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "KMID",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &m.KMID },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "Pub Key Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &m.PubKeyHashAlg },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:   7,
			Name: fmt.Sprintf("Hash: Array of \"Key Manifest\" of length %d", len(m.Hash)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				for idx := range m.Hash {
					size += m.Hash[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &m.Hash },
			Type:  cbnt.ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint16
				err := binary.Read(r, binary.LittleEndian, &count)
				if err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'Hash': %w", err)
				}
				totalN := int64(binary.Size(count))
				m.Hash = make([]Hash, count)
				for idx := range m.Hash {
					n, err := m.Hash[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'Hash[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
			WriteList: func(w io.Writer) (int64, error) {
				count := uint16(len(m.Hash))
				if err := binary.Write(w, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to write the count for field 'Hash': %w", err)
				}
				totalN := int64(binary.Size(count))

				for idx := range m.Hash {
					n, err := m.Hash[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'Hash[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}

				return totalN, nil
			},
		},
		{
			ID:    8,
			Name:  "Key And Signature",
			Size:  func() uint64 { return m.KeyAndSignature.TotalSize() },
			Value: func() any { return &m.KeyAndSignature },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (m *CBnTManifest) SizeOf(id int) (uint64, error) {
	ret, err := m.Common.SizeOf(m, id)
	if err != nil {
		return ret, fmt.Errorf("CBnTManifest: %v", err)
	}

	return ret, nil
}

func (m *CBnTManifest) OffsetOf(id int) (uint64, error) {
	ret, err := m.Common.OffsetOf(m, id)
	if err != nil {
		return ret, fmt.Errorf("CBnTManifest: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the Manifest.
func (m *CBnTManifest) TotalSize() uint64 {
	if m == nil {
		return 0
	}

	return m.Common.TotalSize(m)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (m *CBnTManifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "CBnT Key Manifest", m))
	}
	if m == nil {
		return strings.Join(lines, "\n")
	}

	lines = append(lines, pretty.SubValue(depth+1, "Struct Info", "", &m.StructInfoCBNT, opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Key Manifest Signature Offset", "", &m.KeyManifestSignatureOffset, opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Reserved 2", "", &m.Reserved2, opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Revision", "", &m.Revision, opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "KMSVN", "", &m.KMSVN, opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "KMID", "", &m.KMID, opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "Pub Key Hash Alg", "", &m.PubKeyHashAlg, opts...)...)

	lines = append(lines, pretty.Header(
		depth+1,
		fmt.Sprintf("Hash: Array of \"Key Manifest\" of length %d", len(m.Hash)),
		m.Hash,
	))
	for i := 0; i < len(m.Hash); i++ {
		lines = append(
			lines,
			fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+
				strings.TrimSpace(m.Hash[i].PrettyString(depth+2, true, opts...)),
		)
	}

	if depth < 1 {
		lines = append(lines, "")
	}

	lines = append(lines, pretty.SubValue(depth+1, "Key And Signature", "", &m.KeyAndSignature, opts...)...)

	if depth < 2 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// Print prints the Key Manifest.
func (m *CBnTManifest) Print() {
	if len(m.KeyAndSignature.Signature.Data) < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
