// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bg

import (
	"crypto"
	"crypto/rand"
	"fmt"
)

var (
	// RandReader exports the rand.Reader
	RandReader = rand.Reader
)

// Signature exports the Signature structure
type Signature struct {
	SigScheme Algorithm `json:"sigScheme"`
	Version   uint8     `require:"0x10" json:"sigVersion,omitempty"`
	KeySize   BitSize   `json:"sigKeysize,omitempty"`
	HashAlg   Algorithm `json:"sigHashAlg"`
	Data      []byte    `countValue:"KeySize.InBytes()" prettyValue:"dataPrettyValue()" json:"sigData"`
}

func (m Signature) dataPrettyValue() interface{} {
	r, _ := m.SignatureData()
	return r
}

// SignatureData parses field Data and returns the signature as one of these types:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (m Signature) SignatureData() (SignatureDataInterface, error) {
	switch m.SigScheme {
	case AlgRSASSA:
		return SignatureRSAASA(m.Data), nil
	}

	return nil, fmt.Errorf("unexpected signature scheme: %s", m.SigScheme)
}

// SetSignatureByData sets all the fields of the structure Signature by
// accepting one of these types as the input argument `sig`:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (m *Signature) SetSignatureByData(sig SignatureDataInterface, hashAlgo Algorithm) error {
	err := m.SetSignatureData(sig)
	if err != nil {
		return err
	}

	switch sig := sig.(type) {
	case SignatureRSAASA:
		m.SigScheme = AlgRSASSA
		if hashAlgo.IsNull() {
			m.HashAlg = AlgSHA256
		} else {
			m.HashAlg = hashAlgo
		}
		m.KeySize.SetInBytes(uint16(len(m.Data)))
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
func (m *Signature) SetSignatureData(sig SignatureDataInterface) error {
	switch sig := sig.(type) {
	case SignatureRSAASA:
		m.Data = sig
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
func (m *Signature) SetSignature(signAlgo Algorithm, privKey crypto.Signer, signedData []byte) error {
	m.Version = 0x10
	signData, err := NewSignatureData(signAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}

	err = m.SetSignatureByData(signData, AlgNull)
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
func (m *Signature) FillSignature(signAlgo Algorithm, pubKey crypto.PublicKey, signedData []byte, hashAlgo Algorithm) error {
	m.Version = 0x10
	signData, err := NewSignatureByData(signAlgo, pubKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}

	err = m.SetSignatureByData(signData, hashAlgo)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}
