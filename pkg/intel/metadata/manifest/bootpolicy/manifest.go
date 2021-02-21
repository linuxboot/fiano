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
	BPMH `rehashValue:"rehashedBPMH()" json:"bpm_Header"`
	SE   []SE      `json:"bpm_SE"`
	TXTE *TXT      `json:"bpm_TXTE,omitempty"`
	Res  *Reserved `json:"bpm_reserved,omitempty"`
	// PrettyString: PCDE: Platform Config Data
	PCDE *PCD `json:"bpm_PCDE,omitempty"`
	// PrettyString: PME: Platform Manufacturer
	PME *PM `json:"bpm_PME,omitempty"`
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpm_Signature"`
}

func (bpm Manifest) StructInfo() StructInfo {
	return bpm.BPMH.StructInfo
}
