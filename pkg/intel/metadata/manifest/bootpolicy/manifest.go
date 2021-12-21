//go:generate manifestcodegen

package bootpolicy

import (
	"bytes"
	"fmt"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/intel/metadata/manifest"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// StructInfo is the common header of any element.
type StructInfo = manifest.StructInfo

// Manifest is a boot policy manifest
//
// PrettyString: Boot Policy Manifest
type Manifest struct {
	// BPMH is the header of the boot policy manifest
	//
	// PrettyString: BPMH: Header
	BPMH `rehashValue:"rehashedBPMH()" json:"bpmHeader"`

	SE   []SE      `json:"bpmSE"`
	TXTE *TXT      `json:"bpmTXTE,omitempty"`
	Res  *Reserved `json:"bpmReserved,omitempty"`

	// PCDE is the platform configuration data element
	//
	// PrettyString: PCDE: Platform Config Data
	PCDE *PCD `json:"bpmPCDE,omitempty"`

	// PME is the platform manufacturer element
	//
	// PrettyString: PME: Platform Manufacturer
	PME *PM `json:"bpmPME,omitempty"`

	// PMSE is the signature element
	//
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

// StructInfo is the information about how to parse the structure.
func (bpm Manifest) StructInfo() StructInfo {
	return bpm.BPMH.StructInfo
}

// ValidateIBB returns an error if IBB segments does not match the signature
func (bpm *Manifest) ValidateIBB(firmware uefi.Firmware) error {
	if len(bpm.SE[0].DigestList.List) == 0 {
		return fmt.Errorf("no IBB hashes")
	}

	digest := bpm.SE[0].DigestList.List[0] // [0] instead of range -- is intentionally

	h, err := digest.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash function: %v", digest.HashAlg)
	}

	for _, _range := range bpm.IBBDataRanges(uint64(len(firmware.Buf()))) {
		if _, err := h.Write(firmware.Buf()[_range.Offset:_range.End()]); err != nil {
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
//     calculateOffsetFromPhysAddr(0xffffffff, 0x1000) == 0xfff
//     calculateOffsetFromPhysAddr(0xffffffc0, 0x1000) == 0xfc0
func calculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	const basePhysAddr = 1 << 32 // "4GiB"
	startAddr := basePhysAddr - imageSize
	return physAddr - startAddr
}
