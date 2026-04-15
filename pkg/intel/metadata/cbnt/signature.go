// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbnt

import (
	"crypto"
	"fmt"
	"math/big"

	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type Signature struct {
	Common
	SigScheme Algorithm `json:"sigScheme"`
	Version   uint8     `require:"0x10" json:"sigVersion,omitempty"`
	KeySize   BitSize   `json:"sigKeysize,omitempty"`
	HashAlg   Algorithm `json:"sigHashAlg"`
	Data      []byte    `countValue:"KeySize.InBytes()" prettyValue:"dataPrettyValue()" json:"sigData"`
}

// NewSignature returns a new instance of Signature with
// all default values set.
func NewSignature() *Signature {
	s := &Signature{}
	// Set through tag "required":
	s.Version = 0x10
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Signature) Validate() error {
	// See tag "require"
	if s.Version != 0x10 {
		return fmt.Errorf("field 'Version' expects value '0x10', but has %v", s.Version)
	}

	return nil
}

// ReadFrom reads the Signature from 'r' in format defined in the document #575623.
func (s *Signature) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// WriteTo writes the Signature into 'w' in format defined in
// the document #575623.
func (s *Signature) WriteTo(w io.Writer) (int64, error) {
	return s.Common.WriteTo(w, s)
}

func (s *Signature) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Sig Scheme",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.SigScheme },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    1,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Key Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.KeySize },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.HashAlg },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "Data",
			Size:  func() uint64 { return uint64(s.KeySize.InBytes()) },
			Value: func() any { return &s.Data },
			Type:  ManifestFieldArrayDynamicWithSize,
		},
	}
}

func (s *Signature) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *Signature) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the Signature.
func (s *Signature) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Signature) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Signature", opts...)
}

func (s Signature) dataPrettyValue() any {
	r, _ := s.SignatureData()
	return r
}

// SignatureData parses field Data and returns the signature as one of these types:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (s Signature) SignatureData() (SignatureDataInterface, error) {
	switch s.SigScheme {
	case AlgRSAPSS:
		return SignatureRSAPSS(s.Data), nil
	case AlgRSASSA:
		return SignatureRSAASA(s.Data), nil
	case AlgECDSA:
		if len(s.Data) != 64 && len(s.Data) != 96 {
			return nil, fmt.Errorf("invalid length of the signature data: %d (expected 64 or 96)", len(s.Data))
		}
		return SignatureECDSA{
			R: new(big.Int).SetBytes(reverseBytes(s.Data[:len(s.Data)/2])),
			S: new(big.Int).SetBytes(reverseBytes(s.Data[len(s.Data)/2:])),
		}, nil
	case AlgSM2:
		if len(s.Data) != 64 && len(s.Data) != 96 {
			return nil, fmt.Errorf("invalid length of the signature data: %d (expected 64 or 96)", len(s.Data))
		}
		return SignatureSM2{
			R: new(big.Int).SetBytes(reverseBytes(s.Data[:len(s.Data)/2])),
			S: new(big.Int).SetBytes(reverseBytes(s.Data[len(s.Data)/2:])),
		}, nil
	}

	return nil, fmt.Errorf("unexpected signature scheme: %s", s.SigScheme)
}

// SetSignatureByData sets all the fields of the structure Signature by
// accepting one of these types as the input argument `sig`:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (s *Signature) SetSignatureByData(sig SignatureDataInterface, hashAlgo Algorithm) error {
	err := s.SetSignatureData(sig)
	if err != nil {
		return err
	}

	switch sig := sig.(type) {
	case SignatureRSAPSS:
		s.SigScheme = AlgRSAPSS
		if hashAlgo.IsNull() {
			s.HashAlg = AlgSHA384
		} else {
			s.HashAlg = hashAlgo
		}
		s.KeySize.SetInBytes(uint16(len(s.Data)))
	case SignatureRSAASA:
		s.SigScheme = AlgRSASSA
		if hashAlgo.IsNull() {
			s.HashAlg = AlgSHA256
		} else {
			s.HashAlg = hashAlgo
		}
		s.KeySize.SetInBytes(uint16(len(s.Data)))
	case SignatureECDSA:
		s.SigScheme = AlgECDSA
		if hashAlgo.IsNull() {
			s.HashAlg = AlgSHA512
		} else {
			s.HashAlg = hashAlgo
		}
		s.KeySize.SetInBits(uint16(sig.R.BitLen()))
	case SignatureSM2:
		s.SigScheme = AlgSM2
		if hashAlgo.IsNull() {
			s.HashAlg = AlgSM3
		} else {
			s.HashAlg = hashAlgo
		}
		s.KeySize.SetInBits(uint16(sig.R.BitLen()))
	default:
		return fmt.Errorf("unexpected signature type: %T", sig)
	}
	return nil
}

// SetSignatureData sets the value of the field Data by accepting one of these
// types as the input argument `sig`:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (s *Signature) SetSignatureData(sig SignatureDataInterface) error {
	switch sig := sig.(type) {
	case SignatureRSAPSS:
		s.Data = sig
	case SignatureRSAASA:
		s.Data = sig
	case SignatureECDSA, SignatureSM2:
		var r, p *big.Int
		switch sig := sig.(type) {
		case SignatureECDSA:
			r, p = sig.R, sig.S
		case SignatureSM2:
			r, p = sig.R, sig.S
		default:
			return fmt.Errorf("internal error")
		}
		if r.BitLen() != p.BitLen() {
			return fmt.Errorf("the length of component R (%d) is not equal to the length of component S (%d)", r.BitLen(), p.BitLen())
		}
		if r.BitLen() != 256 && r.BitLen() != 384 {
			return fmt.Errorf("component R (or S) size should be 256 or 384 bites (not %d)", r.BitLen())
		}
		s.Data = make([]byte, r.BitLen()/8+p.BitLen()/8)
		copy(s.Data[:], reverseBytes(r.Bytes()))
		copy(s.Data[r.BitLen()/8:], reverseBytes(p.Bytes()))
	default:
		return fmt.Errorf("unexpected signature type: %T", sig)
	}
	return nil
}

// SetSignature calculates the signature accordingly to arguments signAlgo,
// privKey and signedData; and sets all the fields of the structure Signature.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (s *Signature) SetSignature(signAlgo Algorithm, hashAlgo Algorithm, privKey crypto.Signer, signedData []byte) error {
	s.Version = 0x10
	s.HashAlg = hashAlgo
	signData, err := NewSignatureData(signAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}
	err = s.SetSignatureByData(signData, s.HashAlg)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}

// FillSignature sets the signature accordingly to arguments signAlgo,
// pubKey and signedData; and sets all the fields of the structure Signature.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (s *Signature) FillSignature(signAlgo Algorithm, pubKey crypto.PublicKey, signedData []byte, hashAlgo Algorithm) error {
	s.Version = 0x10
	signData, err := NewSignatureByData(signAlgo, pubKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}

	err = s.SetSignatureByData(signData, hashAlgo)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}
