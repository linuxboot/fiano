// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cbntbootpolicy provides Boot Policy Manifest and its child
// structures representation
package cbntbootpolicy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"github.com/linuxboot/fiano/pkg/uefi"
)

type Manifest interface {
	cbnt.Manifest
}

// NewManifest returns a new instance of Manifest with
// all default values set.
func NewManifest(bgv cbnt.BootGuardVersion) (Manifest, error) {
	bpmh, err := NewBPMH(bgv)
	if err != nil {
		return nil, err
	}

	pmse, err := NewSignature(bgv)
	if err != nil {
		return nil, err
	}

	switch bgv {
	case cbnt.Version10:
		bgBPMH, ok := bpmh.(*BPMHBG)
		if !ok {
			return nil, fmt.Errorf("unexpected BPMH type %T for BG", bpmh)
		}
		m := &ManifestBG{BPMHBG: *bgBPMH, PMSE: *pmse}
		m.Rehash()
		return m, nil
	case cbnt.Version20, cbnt.Version21:
		cbntBPMH, ok := bpmh.(*BPMHCBnT)
		if !ok {
			return nil, fmt.Errorf("unexpected BPMH type %T for CBnT", bpmh)
		}
		m := &ManifestCBnT{BPMHCBnT: *cbntBPMH, PMSE: *pmse}
		m.Rehash()
		return m, nil
	default:
		return nil, fmt.Errorf("version not supported")
	}
}

// PrettyString: Boot Policy Manifest
type ManifestBG struct {
	cbnt.Common
	// PrettyString: BPMH: Header
	BPMHBG `rehashValue:"rehashedBPMH()" json:"bpmHeader"`
	SE     []SEBG `json:"bpmSE"`
	// PrettyString: PME: Platform Manufacturer
	PME *PMBG `json:"bpmPME,omitempty"`
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

func (s ManifestBG) MarshalJSON() ([]byte, error) {
	type signatureJSON struct {
		StructInfoID      cbnt.StructureID  `json:"StructInfoID"`
		StructInfoVersion uint8             `json:"StructInfoVersion"`
		SigKeySignature   cbnt.KeySignature `json:"sigKeySignature"`
	}

	type manifestBGJSON struct {
		BPMHBG BPMHBG        `json:"bpmHeader"`
		SE     []SEBG        `json:"bpmSE"`
		PME    *PMBG         `json:"bpmPME,omitempty"`
		PMSE   signatureJSON `json:"bpmSignature"`
	}

	sigInfo := cbnt.StructInfoBG{}
	if info, ok := s.PMSE.StructInfo.(cbnt.StructInfoBG); ok {
		sigInfo = info
	}

	out := manifestBGJSON{
		BPMHBG: s.BPMHBG,
		SE:     s.SE,
		PME:    s.PME,
		PMSE: signatureJSON{
			StructInfoID:      sigInfo.ID,
			StructInfoVersion: sigInfo.Version,
			SigKeySignature:   s.PMSE.KeySignature,
		},
	}

	return json.Marshal(out)
}

func (s *ManifestBG) UnmarshalJSON(data []byte) error {
	type signatureJSON struct {
		StructInfoID      cbnt.StructureID  `json:"StructInfoID"`
		StructInfoVersion uint8             `json:"StructInfoVersion"`
		SigKeySignature   cbnt.KeySignature `json:"sigKeySignature"`
	}

	type manifestBGJSON struct {
		BPMHBG BPMHBG        `json:"bpmHeader"`
		SE     []SEBG        `json:"bpmSE"`
		PME    *PMBG         `json:"bpmPME,omitempty"`
		PMSE   signatureJSON `json:"bpmSignature"`
	}

	var in manifestBGJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}

	s.BPMHBG = in.BPMHBG
	s.SE = in.SE
	s.PME = in.PME

	structInfo := cbnt.StructInfoBG{
		ID:      in.PMSE.StructInfoID,
		Version: in.PMSE.StructInfoVersion,
	}
	if structInfo.ID == (cbnt.StructureID{}) {
		copy(structInfo.ID[:], []byte(StructureIDSignature))
	}
	if structInfo.Version == 0 {
		structInfo.Version = 0x10
	}

	s.PMSE = Signature{
		StructInfo:   structInfo,
		KeySignature: in.PMSE.SigKeySignature,
	}

	return nil
}

// PrettyString: Boot Policy Manifest
type ManifestCBnT struct {
	cbnt.Common
	// BPMH is the header of the boot policy manifest
	//
	// PrettyString: BPMH: Header
	BPMHCBnT `rehashValue:"rehashedBPMH()" json:"bpmHeader"`

	SE   []SECBnT  `json:"bpmSE"`
	TXTE *TXT      `json:"bpmTXTE,omitempty"`
	Res  *Reserved `json:"bpmReserved,omitempty"`

	// PCDE is the platform configuration data element
	//
	// PrettyString: PCDE: Platform Config Data
	PCDE *PCD `json:"bpmPCDE,omitempty"`

	// PME is the platform manufacturer element
	//
	// PrettyString: PME: Platform Manufacturer
	PME *PMCBnT `json:"bpmPME,omitempty"`

	// PMSE is the signature element
	//
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

func (s ManifestCBnT) MarshalJSON() ([]byte, error) {
	type signatureJSON struct {
		StructInfoID          cbnt.StructureID  `json:"StructInfoID"`
		StructInfoVersion     uint8             `json:"StructInfoVersion"`
		StructInfoVariable0   uint8             `json:"StructInfoVariable0"`
		StructInfoElementSize uint16            `json:"StructInfoElementSize"`
		SigKeySignature       cbnt.KeySignature `json:"sigKeySignature"`
	}

	type manifestCBnTJSON struct {
		BPMHCBnT BPMHCBnT      `json:"bpmHeader"`
		SE       []SECBnT      `json:"bpmSE"`
		TXTE     *TXT          `json:"bpmTXTE,omitempty"`
		Res      *Reserved     `json:"bpmReserved,omitempty"`
		PCDE     *PCD          `json:"bpmPCDE,omitempty"`
		PME      *PMCBnT       `json:"bpmPME,omitempty"`
		PMSE     signatureJSON `json:"bpmSignature"`
	}

	sigInfo := cbnt.StructInfoCBNT{}
	if info, ok := s.PMSE.StructInfo.(cbnt.StructInfoCBNT); ok {
		sigInfo = info
	}

	out := manifestCBnTJSON{
		BPMHCBnT: s.BPMHCBnT,
		SE:       s.SE,
		TXTE:     s.TXTE,
		Res:      s.Res,
		PCDE:     s.PCDE,
		PME:      s.PME,
		PMSE: signatureJSON{
			StructInfoID:          sigInfo.ID,
			StructInfoVersion:     sigInfo.Version,
			StructInfoVariable0:   sigInfo.Variable0,
			StructInfoElementSize: sigInfo.ElementSize,
			SigKeySignature:       s.PMSE.KeySignature,
		},
	}

	return json.Marshal(out)
}

func (s *ManifestCBnT) UnmarshalJSON(data []byte) error {
	type signatureJSON struct {
		StructInfoID          cbnt.StructureID  `json:"StructInfoID"`
		StructInfoVersion     uint8             `json:"StructInfoVersion"`
		StructInfoVariable0   uint8             `json:"StructInfoVariable0"`
		StructInfoElementSize uint16            `json:"StructInfoElementSize"`
		SigKeySignature       cbnt.KeySignature `json:"sigKeySignature"`
	}

	type manifestCBnTJSON struct {
		BPMHCBnT BPMHCBnT      `json:"bpmHeader"`
		SE       []SECBnT      `json:"bpmSE"`
		TXTE     *TXT          `json:"bpmTXTE,omitempty"`
		Res      *Reserved     `json:"bpmReserved,omitempty"`
		PCDE     *PCD          `json:"bpmPCDE,omitempty"`
		PME      *PMCBnT       `json:"bpmPME,omitempty"`
		PMSE     signatureJSON `json:"bpmSignature"`
	}

	var in manifestCBnTJSON
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}

	s.BPMHCBnT = in.BPMHCBnT
	s.SE = in.SE
	s.TXTE = in.TXTE
	s.Res = in.Res
	s.PCDE = in.PCDE
	s.PME = in.PME

	structInfo := cbnt.StructInfoCBNT{
		ID:          in.PMSE.StructInfoID,
		Version:     in.PMSE.StructInfoVersion,
		Variable0:   in.PMSE.StructInfoVariable0,
		ElementSize: in.PMSE.StructInfoElementSize,
	}
	if structInfo.ID == (cbnt.StructureID{}) {
		copy(structInfo.ID[:], []byte(StructureIDSignature))
	}
	if structInfo.Version == 0 {
		structInfo.Version = 0x20
	}

	s.PMSE = Signature{
		StructInfo:   structInfo,
		KeySignature: in.PMSE.SigKeySignature,
	}

	return nil
}

// fieldIndexByStructID returns the position index within
// structure Manifest of the field by its StructureID
// (see document #575623, an example of StructureID value is "__KEYM__").
func (ManifestBG) fieldIndexByStructID(structID string) int {
	switch structID {
	case StructureIDBPMH:
		return 0
	case StructureIDSE:
		return 1
	case StructureIDPM:
		return 2
	case StructureIDSignature:
		return 3
	}

	return -1
}

// fieldNameByIndex returns the name of the field by its position number
// within structure Manifest.
func (ManifestBG) fieldNameByIndex(fieldIndex int) string {
	switch fieldIndex {
	case 0:
		return "BPMH"
	case 1:
		return "SE"
	case 2:
		return "PME"
	case 3:
		return "PMSE"
	}

	return fmt.Sprintf("invalidFieldIndex_%d", fieldIndex)
}

// Validate (recursively) checks the structure if there are any unexpected values.
func (s *ManifestBG) Validate() error {
	if err := s.BPMHBG.Validate(); err != nil {
		return fmt.Errorf("error on field 'BPMH': %w", err)
	}
	expectedValue := s.rehashedBPMH()
	if s.BPMHBG != expectedValue {
		return fmt.Errorf("field 'BPMH' expects write-value '%v', but has %v", expectedValue, s.BPMHBG)
	}
	if err := s.PMSE.Validate(); err != nil {
		return fmt.Errorf("error on field 'PMSE': %w", err)
	}

	return nil
}

func (s *ManifestBG) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "BPMH",
			Size:  func() uint64 { return s.BPMHBG.TotalSize() },
			Value: func() any { return &s.BPMHBG },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   1,
			Name: fmt.Sprintf("SE: Array of \"Boot Policy Manifest\" of length %d", len(s.SE)),
			Size: func() uint64 {
				var size uint64
				for idx := range s.SE {
					size += s.SE[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.SE },
			Type:  cbnt.ManifestFieldList,
			WriteList: func(w io.Writer) (int64, error) {
				totalN := int64(0)
				for idx := range s.SE {
					n, err := s.SE[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'SE[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
		},
		{
			ID:   2,
			Name: "PME",
			Size: func() uint64 {
				if s.PME == nil {
					return 0
				}
				return s.PME.TotalSize()
			},
			Value: func() any {
				if s.PME == nil {
					return nil
				}
				return s.PME
			},
			Type: cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    3,
			Name:  "PMSE",
			Size:  func() uint64 { return s.PMSE.TotalSize() },
			Value: func() any { return &s.PMSE },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *ManifestBG) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Manifest: %v", err)
	}
	return ret, nil
}

func (s *ManifestBG) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Manifest: %v", err)
	}
	return ret, nil
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
// Note that the BPM is a special case: we do not use common way of handling the reading here.
func (s *ManifestBG) ReadFrom(r io.Reader) (returnN int64, returnErr error) {
	var missingFieldsByIndices = [4]bool{
		0: true,
		3: true,
	}
	defer func() {
		if returnErr != nil {
			return
		}
		for fieldIndex, v := range missingFieldsByIndices {
			if v {
				returnErr = fmt.Errorf("field '%s' is missing", s.fieldNameByIndex(fieldIndex))
				break
			}
		}
	}()
	var totalN int64
	previousFieldIndex := int(-1)
	for {
		var structInfo cbnt.StructInfoBG
		err := binary.Read(r, binary.LittleEndian, &structInfo)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return totalN, nil
		}
		if err != nil {
			return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
		}
		structID := structInfo.ID.String()
		fieldIndex := s.fieldIndexByStructID(structID)
		if fieldIndex < 0 {
			// Let's just warn about unknown struct, no need to fail completely
			fmt.Printf("warning: unknown structure ID: %s\n", structID)
			continue
		}
		totalN += int64(binary.Size(structInfo))
		if cbnt.StrictOrderCheck && fieldIndex < previousFieldIndex {
			return totalN, fmt.Errorf("invalid order of fields (%d < %d): structure '%s' is out of order", fieldIndex, previousFieldIndex, structID)
		}
		missingFieldsByIndices[fieldIndex] = false

		var n int64
		switch structID {
		case StructureIDBPMH:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'BPMH' is not a slice, but multiple elements found")
			}
			s.SetStructInfo(structInfo)
			n, err = s.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field BPMH at %d: %w", totalN, err)
			}
		case StructureIDSE:
			var el SEBG
			el.SetStructInfo(structInfo)
			n, err = el.ReadFromHelper(r, false)
			s.SE = append(s.SE, el)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field SE at %d: %w", totalN, err)
			}
		case StructureIDPM:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PME' is not a slice, but multiple elements found")
			}
			s.PME = &PMBG{}
			s.PME.SetStructInfo(structInfo)
			n, err = s.PME.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PME at %d: %w", totalN, err)
			}
		case StructureIDSignature:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PMSE' is not a slice, but multiple elements found")
			}
			s.PMSE.SetStructInfo(structInfo)
			n, err = s.PMSE.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PMSE at %d: %w", totalN, err)
			}
		default:
			return totalN, fmt.Errorf("there is no field with structure ID '%s' in Manifest", structInfo.ID)
		}
		totalN += n
		previousFieldIndex = fieldIndex
	}

}

func (s *ManifestBG) RehashRecursive() {
	s.Rehash()
}

func (s *ManifestBG) Rehash() {
	s.BPMHBG = s.rehashedBPMH()
}

func (s *ManifestBG) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

func (s *ManifestBG) TotalSize() uint64 {
	if s == nil {
		return 0
	}
	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *ManifestBG) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Boot Policy Manifest", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "BPMH: Header", "", &s.BPMHBG, opts...)...)
	// ManifestFieldType is elementList
	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("SE: Array of \"Boot Policy Manifest\" of length %d", len(s.SE)), s.SE))
	for i := 0; i < len(s.SE); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.SE[i].PrettyString(depth+2, true)))
	}
	if depth < 1 {
		lines = append(lines, "")
	}
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PME: Platform Manufacturer", "", s.PME, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PMSE: Signature", "", &s.PMSE, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (s *ManifestBG) StructInfo() cbnt.StructInfo {
	return s.StructInfoBG
}

func (s *ManifestBG) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoBG
}

func (s *ManifestBG) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoBG = newStructInfo.(cbnt.StructInfoBG)
}

func (s *ManifestBG) ValidateIBB(firmware uefi.Firmware) error {
	if s.SE[0].Digest.TotalSize() == 0 {
		return fmt.Errorf("no IBB hashes")
	}

	digest := s.SE[0].Digest
	h, err := digest.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash function: %v", digest.HashAlg)
	}

	imgSize := uint64((len(firmware.Buf())))
	if ifdSize, ifdErr := FlashSizeIFD(firmware.Buf()); ifdErr == nil && ifdSize > 0 && ifdSize <= imgSize {
		imgSize = ifdSize
	}

	for _, r := range s.IBBDataRanges(imgSize) {
		if _, err := h.Write(firmware.Buf()[r.Offset:r.End()]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	}
	hashValue := h.Sum(nil)

	if !bytes.Equal(hashValue, digest.HashBuffer) {
		return fmt.Errorf("IBB %s hash mismatch: %X != %X", digest.HashAlg, hashValue, digest.HashBuffer)
	}

	return nil
}

// IBBDataRanges returns data ranges of IBB.
func (s *ManifestBG) IBBDataRanges(firmwareSize uint64) pkgbytes.Ranges {
	return ibbDataRanges(s.SE[0].IBBSegments, firmwareSize)
}

func (s *ManifestBG) rehashedBPMH() BPMHBG {
	return s.BPMHBG
}

func (s ManifestBG) Print() {
	fmt.Printf("%v", s.BPMHBG.PrettyString(1, true))
	for _, item := range s.SE {
		fmt.Printf("%v", item.PrettyString(1, true))
	}

	if s.PME != nil {
		fmt.Printf("%v\n", s.PME.PrettyString(1, true))
	} else {
		fmt.Println("  --PME--\n\tnot set!(optional)")
	}

	if len(s.PMSE.Signature.Data) < 1 {
		fmt.Printf("%v\n", s.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --PMSE--\n\tBoot Policy Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", s.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}

func (ManifestCBnT) fieldIndexByStructID(structID string) int {
	switch structID {
	case StructureIDBPMH:
		return 0
	case StructureIDSE:
		return 1
	case StructureIDTXT:
		return 2
	case StructureIDReserved:
		return 3
	case StructureIDPCD:
		return 4
	case StructureIDPM:
		return 5
	case StructureIDSignature:
		return 6
	}

	return -1
}

func (ManifestCBnT) fieldNameByIndex(fieldIndex int) string {
	switch fieldIndex {
	case 0:
		return "BPMH"
	case 1:
		return "SE"
	case 2:
		return "TXTE"
	case 3:
		return "Res"
	case 4:
		return "PCDE"
	case 5:
		return "PME"
	case 6:
		return "PMSE"
	}

	return fmt.Sprintf("invalidFieldIndex_%d", fieldIndex)
}

// Validate (recursively) checks the structure if there are any unexpected values.
func (s *ManifestCBnT) Validate() error {
	if err := s.BPMHCBnT.Validate(); err != nil {
		return fmt.Errorf("error on field 'BPMH': %w", err)
	}
	if s.BPMHCBnT != s.rehashedBPMH() {
		return fmt.Errorf("field 'BPMH' expects write-value '%v', but has %v", s.rehashedBPMH(), s.BPMHCBnT)
	}
	if err := s.PMSE.Validate(); err != nil {
		return fmt.Errorf("error on field 'PMSE': %w", err)
	}

	if s.PCDE != nil {
		if err := s.PCDE.Validate(); err != nil {
			return fmt.Errorf("error on field 'PCDE': %w", err)
		}
	}

	return nil
}

func (s *ManifestCBnT) Layout() []cbnt.LayoutField {
	// All fields marked with omitempty have to be checked for being
	// empty in the clousure for Value. Otherwise we risk some nasty errors
	// even with valid (i.e. compliant with the spec) Manifests.
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "BPMH: Header",
			Size:  func() uint64 { return s.BPMHCBnT.TotalSize() },
			Value: func() any { return &s.BPMHCBnT },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   1,
			Name: fmt.Sprintf("SE: Array of \"Boot Policy Manifest\" of length %d", len(s.SE)),
			Size: func() uint64 {
				var size uint64
				for idx := range s.SE {
					size += s.SE[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.SE },
			Type:  cbnt.ManifestFieldList,
			WriteList: func(w io.Writer) (int64, error) {
				totalN := int64(0)
				for idx := range s.SE {
					n, err := s.SE[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'SE[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
		},
		{
			ID:   2,
			Name: "TXTE",
			Size: func() uint64 {
				if s.TXTE == nil {
					return 0
				}
				return s.TXTE.TotalSize()
			},
			Value: func() any {
				if s.TXTE == nil {
					return nil
				}
				return s.TXTE
			},
			Type: cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   3,
			Name: "Res",
			Size: func() uint64 {
				if s.Res == nil {
					return 0
				}
				return s.Res.TotalSize()
			},
			Value: func() any {
				if s.Res == nil {
					return nil
				}
				return s.Res
			},
			Type: cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   4,
			Name: "PCDE: Platform Config Data",
			Size: func() uint64 {
				if s.PCDE == nil {
					return 0
				}
				return s.PCDE.TotalSize()
			},
			Value: func() any {
				if s.PCDE == nil {
					return nil
				}
				return s.PCDE
			},
			Type: cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   5,
			Name: "PME: Platform Manufacturer",
			Size: func() uint64 {
				if s.PME == nil {
					return 0
				}
				return s.PME.TotalSize()
			},
			Value: func() any {
				if s.PME == nil {
					return nil
				}
				return s.PME
			},
			Type: cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    6,
			Name:  "PMSE: Signature",
			Size:  func() uint64 { return s.PMSE.TotalSize() },
			Value: func() any { return &s.PMSE },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *ManifestCBnT) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Manifest: %v", err)
	}

	return ret, nil
}

func (s *ManifestCBnT) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Manifest: %v", err)
	}

	return ret, nil
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
// Same note as above: this is an exception from the rule of usijg common approach.
func (s *ManifestCBnT) ReadFrom(r io.Reader) (returnN int64, returnErr error) {
	var missingFieldsByIndices = [7]bool{
		0: true,
		6: true,
	}
	defer func() {
		if returnErr != nil {
			return
		}
		for fieldIndex, v := range missingFieldsByIndices {
			if v {
				returnErr = fmt.Errorf("field '%s' is missing", s.fieldNameByIndex(fieldIndex))
				break
			}
		}
	}()
	var totalN int64
	previousFieldIndex := int(-1)
	for {
		var structInfo cbnt.StructInfoCBNT
		err := binary.Read(r, binary.LittleEndian, &structInfo)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return totalN, nil
		}
		if err != nil {
			return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
		}
		structID := structInfo.ID.String()
		fieldIndex := s.fieldIndexByStructID(structID)
		if fieldIndex < 0 {
			fmt.Printf("warning: unknown structure ID: %s\n", structID)
			continue
		}
		totalN += int64(binary.Size(structInfo))
		if cbnt.StrictOrderCheck && fieldIndex < previousFieldIndex {
			return totalN, fmt.Errorf("invalid order of fields (%d < %d): structure '%s' is out of order", fieldIndex, previousFieldIndex, structID)
		}
		missingFieldsByIndices[fieldIndex] = false

		var n int64
		switch structID {
		case StructureIDBPMH:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'BPMH' is not a slice, but multiple elements found")
			}
			s.SetStructInfo(structInfo)
			n, err = s.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field BPMH at %d: %w", totalN, err)
			}
		case StructureIDSE:
			var el SECBnT
			el.SetStructInfo(structInfo)
			n, err = el.ReadFromHelper(r, false)
			s.SE = append(s.SE, el)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field SE at %d: %w", totalN, err)
			}
		case StructureIDTXT:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'TXTE' is not a slice, but multiple elements found")
			}
			s.TXTE = &TXT{}
			s.TXTE.SetStructInfo(structInfo)
			n, err = s.TXTE.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field TXTE at %d: %w", totalN, err)
			}
		case StructureIDReserved:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'Res' is not a slice, but multiple elements found")
			}
			s.Res = &Reserved{}
			s.Res.SetStructInfo(structInfo)
			n, err = s.Res.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field Res at %d: %w", totalN, err)
			}
		case StructureIDPCD:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PCDE' is not a slice, but multiple elements found")
			}
			s.PCDE = &PCD{}
			s.PCDE.SetStructInfo(structInfo)
			n, err = s.PCDE.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PCDE at %d: %w", totalN, err)
			}
		case StructureIDPM:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PME' is not a slice, but multiple elements found")
			}
			s.PME = &PMCBnT{}
			s.PME.SetStructInfo(structInfo)
			n, err = s.PME.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PME at %d: %w", totalN, err)
			}
		case StructureIDSignature:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PMSE' is not a slice, but multiple elements found")
			}
			s.PMSE.SetStructInfo(structInfo)
			n, err = s.PMSE.ReadFromHelper(r, false)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PMSE at %d: %w", totalN, err)
			}
		default:
			return totalN, fmt.Errorf("there is no field with structure ID '%s' in Manifest", structInfo.ID)
		}
		totalN += n
		previousFieldIndex = fieldIndex
	}
}

func (s *ManifestCBnT) RehashRecursive() {
	s.BPMHCBnT.Rehash()
	for idx := range s.SE {
		s.SE[idx].RehashRecursive()
	}
	if s.TXTE != nil {
		s.TXTE.Rehash()
	}
	if s.Res != nil {
		s.Res.Rehash()
	}
	if s.PCDE != nil {
		s.PCDE.Rehash()
	}
	if s.PME != nil {
		s.PME.Rehash()
	}
	s.Rehash()
}

func (s *ManifestCBnT) Rehash() {
	s.BPMHCBnT = s.rehashedBPMH()
}

func (s *ManifestCBnT) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

func (s *ManifestCBnT) TotalSize() uint64 {
	if s == nil {
		return 0
	}
	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *ManifestCBnT) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Boot Policy Manifest", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "BPMH: Header", "", &s.BPMHCBnT, opts...)...)
	// ManifestFieldType is elementList
	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("SE: Array of \"Boot Policy Manifest\" of length %d", len(s.SE)), s.SE))
	for i := 0; i < len(s.SE); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.SE[i].PrettyString(depth+2, true)))
	}
	if depth < 1 {
		lines = append(lines, "")
	}
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "TXTE", "", s.TXTE, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "Res", "", s.Res, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PCDE: Platform Config Data", "", s.PCDE, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PME: Platform Manufacturer", "", s.PME, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PMSE: Signature", "", &s.PMSE, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (s *ManifestCBnT) StructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

func (s *ManifestCBnT) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

func (s *ManifestCBnT) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// ValidateIBB returns an error if IBB segments does not match the signature.
func (s *ManifestCBnT) ValidateIBB(firmware uefi.Firmware) error {
	if len(s.SE[0].DigestList.List) == 0 {
		return fmt.Errorf("no IBB hashes")
	}

	digest := s.SE[0].DigestList.List[0]
	h, err := digest.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash function: %v", digest.HashAlg)
	}

	imgSize := uint64((len(firmware.Buf())))
	if ifdSize, ifdErr := FlashSizeIFD(firmware.Buf()); ifdErr == nil && ifdSize > 0 && ifdSize <= imgSize {
		imgSize = ifdSize
	}

	for _, r := range s.IBBDataRanges(imgSize) {
		if _, err := h.Write(firmware.Buf()[r.Offset:r.End()]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	}
	hashValue := h.Sum(nil)

	if !bytes.Equal(hashValue, digest.HashBuffer) {
		return fmt.Errorf("IBB %s hash mismatch: %X != %X", digest.HashAlg, hashValue, digest.HashBuffer)
	}

	return nil
}

// IBBDataRanges returns data ranges of IBB.
func (s *ManifestCBnT) IBBDataRanges(firmwareSize uint64) pkgbytes.Ranges {
	return ibbDataRanges(s.SE[0].IBBSegments, firmwareSize)
}

// Helper for IBBDataRanges. Moved to the separate func cause the logic is shared between
// CBnT and BG.
func ibbDataRanges(segments []IBBSegment, firmwareSize uint64) pkgbytes.Ranges {
	var result pkgbytes.Ranges

	for _, seg := range segments {
		if seg.Flags&1 == 1 {
			continue
		}
		startIdx := CalculateOffsetFromPhysAddr(uint64(seg.Base), firmwareSize)
		result = append(result, pkgbytes.Range{Offset: startIdx, Length: uint64(seg.Size)})
	}

	return result
}

// CalculateOffsetFromPhysAddr calculates the offset within an image of a physical address.
func CalculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	const basePhysAddr = 1 << 32
	startAddr := basePhysAddr - imageSize
	return physAddr - startAddr
}

func FlashSizeIFD(buf []byte) (uint64, error) {
	if uint64(len(buf)) < uefi.FlashDescriptorLength {
		return 0, fmt.Errorf("buffer too small for flash descriptior: %d", len(buf))
	}

	fd := uefi.FlashDescriptor{}
	fd.SetBuf(buf[:uefi.FlashDescriptorLength])
	if err := fd.ParseFlashDescriptor(); err != nil {
		return 0, err
	}

	var maxEnd uint64
	for _, fr := range fd.Region.FlashRegions {
		if !fr.Valid() {
			continue
		}
		end := uint64(fr.EndOffset())
		if end > maxEnd {
			maxEnd = end
		}
	}
	if maxEnd == 0 {
		return 0, fmt.Errorf("no valid regions in flash descriptor")
	}

	return maxEnd, nil

}

func (s *ManifestCBnT) rehashedBPMH() BPMHCBnT {
	bpmh := s.BPMHCBnT
	pmseOffs, _ := s.OffsetOf(6)
	keySigOffs, _ := s.PMSE.OffsetOf(1)
	bpmh.KeySignatureOffset = uint16(pmseOffs + keySigOffs)
	return bpmh
}

func (s ManifestCBnT) Print() {
	fmt.Printf("%v", s.BPMHCBnT.PrettyString(1, true))
	for _, item := range s.SE {
		fmt.Printf("%v", item.PrettyString(1, true))
	}
	if s.TXTE != nil {
		fmt.Printf("%v\n", s.TXTE.PrettyString(1, true))
	} else {
		fmt.Printf("  --TXTE--\n\t not set!(optional)\n")
	}

	if s.PCDE != nil {
		fmt.Printf("%v\n", s.PCDE.PrettyString(1, true))
	} else {
		fmt.Println("  --PCDE-- \n\tnot set!(optional)")
	}

	if s.PME != nil {
		fmt.Printf("%v\n", s.PME.PrettyString(1, true))
	} else {
		fmt.Println("  --PME--\n\tnot set!(optional)")
	}

	if len(s.PMSE.Signature.Data) < 1 {
		fmt.Printf("%v\n", s.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --PMSE--\n\tBoot Policy Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", s.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
