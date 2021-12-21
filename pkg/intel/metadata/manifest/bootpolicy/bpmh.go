//go:generate manifestcodegen

package bootpolicy

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

type BPMH struct {
	StructInfo `id:"__ACBP__" version:"0x23" var0:"0x20" var1:"uint16(s.TotalSize())"`

	KeySignatureOffset uint16 `json:"bpmhKeySignatureOffset"`

	BPMRevision uint8 `json:"bpmhRevision"`

	// PrettyString: BPM SVN
	BPMSVN manifest.SVN `json:"bpmhSNV"`
	// PrettyString: ACM SVN Auth
	ACMSVNAuth manifest.SVN `json:"bpmhACMSVN"`

	Reserved0 [1]byte `require:"0" json:"bpmhReserved0,omitemtpy"`

	NEMDataStack Size4K `json:"bpmhNEMStackSize"`
}

// Size4K is a size in units of 4096 bytes.
type Size4K uint16

// InBytes returns the size in bytes.
func (s Size4K) InBytes() uint32 {
	return uint32(s) * 4096
}

// NewSize4K returns the given size as multiple of 4K
func NewSize4K(size uint32) Size4K {
	return Size4K(size / 4096)
}
