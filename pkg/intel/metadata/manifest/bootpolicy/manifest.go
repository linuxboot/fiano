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

// PrettyString: Boot Policy Manifest
type Manifest struct {
	// PrettyString: BPMH: Header
	BPMH `rehashValue:"rehashedBPMH()" json:"bpmHeader"`
	SE   []SE      `json:"bpmSE"`
	TXTE *TXT      `json:"bpmTXTE,omitempty"`
	Res  *Reserved `json:"bpmReserved,omitempty"`
	// PrettyString: PCDE: Platform Config Data
	PCDE *PCD `json:"bpmPCDE,omitempty"`
	// PrettyString: PME: Platform Manufacturer
	PME *PM `json:"bpmPME,omitempty"`
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

func (bpm Manifest) StructInfo() StructInfo {
	return bpm.BPMH.StructInfo
}

func (bpm *Manifest) ValidateIBBs(firmware uefi.Firmware) error {
	if len(bpm.SE[0].DigestList.List) == 0 {
		return fmt.Errorf("no IBB hashes")
	}

	for _, digest := range bpm.SE[0].DigestList.List {
		h, err := digest.HashAlg.Hash()
		if err != nil {
			return fmt.Errorf("invalid hash function: %v", digest.HashAlg)
		}

		for _, seg := range bpm.SE[0].IBBSegments {
			startIdx := consts.CalculateOffsetFromPhysAddr(uint64(seg.Base), uint64(len(firmware.Buf())))
			h.Write(firmware.Buf()[startIdx : startIdx+uint64(seg.Size)])
		}
		hashValue := h.Sum(nil)

		if bytes.Compare(hashValue, digest.HashBuffer) != 0 {
			return fmt.Errorf("IBB %s hash mismatch: %X != %X", digest.HashAlg, hashValue, digest.HashBuffer)
		}
	}

	return nil
}
