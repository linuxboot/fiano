//go:generate manifestcodegen

package key

import (
	"bytes"
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

func (m *Manifest) ValidateBPMKey(bpmKS manifest.KeySignature) error {
	hashCount := 0
	for _, hashEntry := range m.Hash {
		if !hashEntry.Usage.IsSet(UsageBPMSigningPKD) {
			continue
		}

		h, err := hashEntry.Digest.HashAlg.Hash()
		if err != nil {
			return fmt.Errorf("invalid hash algo %v: %w", hashEntry.Digest.HashAlg, err)
		}

		if len(hashEntry.Digest.HashBuffer) != h.Size() {
			return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(hashEntry.Digest.HashBuffer), h.Size())
		}

		switch bpmKS.Key.KeyAlg {
		case manifest.AlgRSA:
			if _, err := h.Write(bpmKS.Key.Data[4:]); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
		default:
			return fmt.Errorf("unsupported key algorithm: %v", bpmKS.Key.KeyAlg)
		}
		digest := h.Sum(nil)

		if !bytes.Equal(hashEntry.Digest.HashBuffer, digest) {
			return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, hashEntry.Digest.HashBuffer, hashEntry.Digest.HashAlg)
		}
		hashCount++
	}

	if hashCount == 0 {
		return fmt.Errorf("no hash of BPM's key was found in KM")
	}

	return nil
}
