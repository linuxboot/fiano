//go:generate manifestcodegen

package bootpolicy

import (
	"bytes"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
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

// ValidateIBBs returns an error if IBB segments does not match the signature
func (bpm *Manifest) ValidateIBBs(firmware uefi.Firmware) error {
	if len(bpm.SE[0].DigestList.List) == 0 {
		return fmt.Errorf("no IBB hashes")
	}

	digest := bpm.SE[0].DigestList.List[0] // [0] instead of range -- is intentionally

	h, err := digest.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash function: %v", digest.HashAlg)
	}

	for _, seg := range bpm.SE[0].IBBSegments {
		if seg.Flags&1 == 1 {
			continue
		}
		startIdx := consts.CalculateOffsetFromPhysAddr(uint64(seg.Base), uint64(len(firmware.Buf())))
		if _, err := h.Write(firmware.Buf()[startIdx : startIdx+uint64(seg.Size)]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	}
	hashValue := h.Sum(nil)

	if !bytes.Equal(hashValue, digest.HashBuffer) {
		return fmt.Errorf("IBB %s hash mismatch: %X != %X", digest.HashAlg, hashValue, digest.HashBuffer)
	}

	return nil
}
