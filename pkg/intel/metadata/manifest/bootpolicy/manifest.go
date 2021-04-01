//go:generate manifestcodegen

package bootpolicy

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
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
