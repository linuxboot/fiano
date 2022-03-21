// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
func (s *KeySignature) Verify(signedData []byte) error {
	sig, err := s.Signature.SignatureData()
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	pk, err := s.Key.PubKey()
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	err = sig.Verify(pk, s.Signature.HashAlg, signedData)
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
func (s *KeySignature) SetSignature(signAlgo Algorithm, hashAlgo Algorithm, privKey crypto.Signer, signedData []byte) error {
	s.Version = 0x10
	err := s.Key.SetPubKey(privKey.Public())
	if err != nil {
		return fmt.Errorf("unable to set public key: %w", err)
	}

	return s.Signature.SetSignature(signAlgo, hashAlgo, privKey, signedData)
}

// SetSignatureAuto generates a signature and sets all the values of KeyManifest,
// accordingly to arguments privKey and signedData.
//
// Signing algorithm will be detected automatically based on the type of the
// provided private key.
func (s *KeySignature) SetSignatureAuto(privKey crypto.Signer, signedData []byte) error {
	s.Version = 0x10
	err := s.Key.SetPubKey(privKey.Public())
	if err != nil {
		return fmt.Errorf("unable to set public key: %w", err)
	}

	return s.SetSignature(0, 0, privKey, signedData)
}

// FillSignature sets a signature and all the values of KeyManifest,
// accordingly to arguments signAlgo, pubKey and signedData.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (s *KeySignature) FillSignature(signAlgo Algorithm, pubKey crypto.PublicKey, signedData []byte, hashAlgo Algorithm) error {
	s.Version = 0x10
	err := s.Key.SetPubKey(pubKey)
	if err != nil {
		return fmt.Errorf("unable to set public key: %w", err)
	}

	return s.Signature.FillSignature(signAlgo, pubKey, signedData, hashAlgo)
}
