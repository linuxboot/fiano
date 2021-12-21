//go:generate manifestcodegen

package bootpolicy

import (
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

// Signature contains the signature of the BPM.
type Signature struct {
	StructInfo            `id:"__PMSG__" version:"0x20" var0:"0" var1:"0"`
	manifest.KeySignature `json:"sig_KeySignature"`
}
