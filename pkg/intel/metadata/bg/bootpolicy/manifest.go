// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bootpolicy

import (
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"

	"github.com/linuxboot/fiano/pkg/intel/metadata/bg"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// StructInfo is the common header of any element.
type StructInfo = bg.StructInfo

// PrettyString: Boot Policy Manifest
type Manifest struct {
	// PrettyString: BPMH: Header
	BPMH `rehashValue:"rehashedBPMH()" json:"bpmHeader"`
	// PrettyString: SE: Header
	SE []SE `json:"bpmSE"`
	// PrettyString: PME: Platform Manufacturer
	PME *PM `json:"bpmPME,omitempty"`
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

// StructInfo is the information about how to parse the structure.
func (bpm Manifest) StructInfo() StructInfo {
	return bpm.BPMH.StructInfo
}

// ValidateIBB returns an error if IBB segments does not match the signature
func (bpm *Manifest) ValidateIBB(firmware uefi.Firmware) error {
	// TODO
	return nil
}

// IBBDataRanges returns data ranges of IBB.
func (bpm *Manifest) IBBDataRanges(firmwareSize uint64) pkgbytes.Ranges {
	var result pkgbytes.Ranges

	for _, seg := range bpm.SE[0].IBBSegments {
		if seg.Flags&1 == 1 {
			continue
		}
		startIdx := calculateOffsetFromPhysAddr(uint64(seg.Base), firmwareSize)
		result = append(result, pkgbytes.Range{Offset: startIdx, Length: uint64(seg.Size)})
	}

	return result
}

// calculateOffsetFromPhysAddr calculates the offset within an image
// of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//
//	calculateOffsetFromPhysAddr(0xffffffff, 0x1000) == 0xfff
//	calculateOffsetFromPhysAddr(0xffffffc0, 0x1000) == 0xfc0
func calculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	const basePhysAddr = 1 << 32 // "4GiB"
	startAddr := basePhysAddr - imageSize
	return physAddr - startAddr
}
