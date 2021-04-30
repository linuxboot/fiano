//go:generate manifestcodegen

package manifest

import (
	"crypto"
	"fmt"
)

// KeySignature combines a public key and a signature in a single structure.
type KeySignature struct {
	Version   uint8     `require:"0x10" json:"ksVersion,omitempty"`
	Key       Key       `json:"ksKey"`
	Signature Signature `json:"ksSignature"`
}

// Verify verifies the builtin signature with the builtin public key.
func (m *KeySignature) Verify(signedData []byte) error {
	sig, err := m.Signature.SignatureData()
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	pk, err := m.Key.PubKey()
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	err = sig.Verify(pk, signedData)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	return nil
}

// SetSignature generates a signature and sets all the values of KeyManifest,
// accordingly to arguments signAlgo, privKey and signedData.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (ks *KeySignature) SetSignature(signAlgo Algorithm, privKey crypto.Signer, signedData []byte) error {
	ks.Version = 0x10
	err := ks.Key.SetPubKey(privKey.Public())
	if err != nil {
		return fmt.Errorf("unable to set public key: %w", err)
	}

	return ks.Signature.SetSignature(signAlgo, privKey, signedData)
}

// SetSignatureAuto generates a signature and sets all the values of KeyManifest,
// accordingly to arguments privKey and signedData.
//
// Signing algorithm will be detected automatically based on the type of the
// provided private key.
func (ks *KeySignature) SetSignatureAuto(privKey crypto.Signer, signedData []byte) error {
	ks.Version = 0x10
	err := ks.Key.SetPubKey(privKey.Public())
	if err != nil {
		return fmt.Errorf("unable to set public key: %w", err)
	}

	return ks.SetSignature(0, privKey, signedData)
}

// FillSignature sets a signature and all the values of KeyManifest,
// accordingly to arguments signAlgo, pubKey and signedData.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (ks *KeySignature) FillSignature(signAlgo Algorithm, pubKey crypto.PublicKey, signedData []byte, hashAlgo Algorithm) error {
	ks.Version = 0x10
	err := ks.Key.SetPubKey(pubKey)
	if err != nil {
		return fmt.Errorf("unable to set public key: %w", err)
	}

	return ks.Signature.FillSignature(signAlgo, pubKey, signedData, hashAlgo)
}
