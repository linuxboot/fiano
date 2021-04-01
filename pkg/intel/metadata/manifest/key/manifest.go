//go:generate manifestcodegen

package key

import (
	"crypto"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

// PrettyString: Key Manifest
type Manifest struct {
	manifest.StructInfo `id:"__KEYM__" version:"0x21" var0:"0" var1:"0"`

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
	KMSVN manifest.SVN `json:"kmSVN"`

	// KMID is the Key Manifest Identifier.
	KMID uint8 `json:"kmID"`

	// PubKeyHashAlg is the hash algorithm of OEM public key digest programmed
	// into the FPF.
	PubKeyHashAlg manifest.Algorithm `json:"kmPubKeyHashAlg"`

	// Hash is the slice of KMHASH_STRUCT (KHS) structures (see table 5-3
	// of the document #575623). Describes BPM pubkey digest (among other).
	Hash []Hash `json:"kmHash"`

	// KeyAndSignature is the Key Manifest signature.
	KeyAndSignature manifest.KeySignature `json:"kmKeySignature"`
}

func (m *Manifest) SetSignature(
	algo manifest.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}
	m.PubKeyHashAlg = m.KeyAndSignature.Signature.HashAlg

	return nil
}
