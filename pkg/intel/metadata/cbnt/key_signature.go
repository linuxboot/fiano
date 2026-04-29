// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"crypto"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type KeySignature struct {
	Common
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

// NewKeySignature returns a new instance of KeySignature with
// all default values set.
func NewKeySignature() *KeySignature {
	s := &KeySignature{}
	// Set through tag "required":
	s.Version = 0x10
	// Recursively initializing a child structure:
	s.Key = *NewKey()
	// Recursively initializing a child structure:
	s.Signature = *NewSignature()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *KeySignature) Validate() error {
	// See tag "require"
	if s.Version != 0x10 {
		return fmt.Errorf("field 'Version' expects value '0x10', but has %v", s.Version)
	}
	// Recursively validating a child structure:
	if err := s.Key.Validate(); err != nil {
		return fmt.Errorf("error on field 'Key': %w", err)
	}
	// Recursively validating a child structure:
	if err := s.Signature.Validate(); err != nil {
		return fmt.Errorf("error on field 'Signature': %w", err)
	}

	return nil
}

// ReadFrom reads the KeySignature from 'r' in format defined in the document #575623.
func (s *KeySignature) ReadFrom(r io.Reader) (int64, error) {
	return s.Common.ReadFrom(r, s)
}

// WriteTo writes the KeySignature into 'w' in format defined in
// the document #575623.
func (s *KeySignature) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

// Layout returns the structure's layout descriptor
func (s *KeySignature) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    1,
			Name:  "Key",
			Size:  func() uint64 { return s.Key.Common.TotalSize(&s.Key) },
			Value: func() any { return &s.Key },
			Type:  ManifestFieldSubStruct,
		},
		{
			ID:    2,
			Name:  "Signature",
			Size:  func() uint64 { return s.Signature.Common.TotalSize(&s.Signature) },
			Value: func() any { return &s.Signature },
			Type:  ManifestFieldSubStruct,
		},
	}
}

// SizeOf returns the size of the structure's field of a given id.
func (s *KeySignature) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// OffsetOf returns the offset of the structure's field of a given id.
func (s *KeySignature) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the KeySignature.
func (s *KeySignature) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *KeySignature) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Key Signature", opts...)
}
