// Copyright 2017-2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package bg

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

var SM2UID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// NewSignatureData returns an implementation of SignatureDataInterface,
// accordingly to signAlgo, privKey and signedData.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func NewSignatureData(
	signAlgo Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) (SignatureDataInterface, error) {
	if signAlgo == 0 {
		// auto-detect the sign algorithm, based on the provided signing key
		switch privKey.(type) {
		case *rsa.PrivateKey:
			signAlgo = AlgRSASSA
		}
	}
	switch signAlgo {
	case AlgRSASSA:
		rsaPrivateKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected private RSA key (type %T), but received %T", rsaPrivateKey, privKey)
		}
		h := sha256.New()
		_, _ = h.Write(signedData)
		bpmHash := h.Sum(nil)
		data, err := rsa.SignPKCS1v15(RandReader, rsaPrivateKey, crypto.SHA256, bpmHash)
		if err != nil {
			return nil, fmt.Errorf("unable to sign with RSASSA the data: %w", err)
		}
		return SignatureRSAASA(data), nil
	}

	return nil, fmt.Errorf("signing algorithm '%s' is not implemented in this library", signAlgo)
}

// NewSignatureByData returns an implementation of SignatureDataInterface,
// accordingly to signAlgo, publicKey and signedData.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func NewSignatureByData(
	signAlgo Algorithm,
	pubKey crypto.PublicKey,
	signedData []byte,
) (SignatureDataInterface, error) {
	if signAlgo == 0 {
		// auto-detect the sign algorithm, based on the provided signing key
		switch pubKey.(type) {
		case *rsa.PublicKey:
			signAlgo = AlgRSASSA
		}
	}
	switch signAlgo {
	case AlgRSASSA:
		return SignatureRSAASA(signedData), nil
	}
	return nil, fmt.Errorf("signing algorithm '%s' is not implemented in this library", signAlgo)
}

// SignatureDataInterface is the interface which abstracts all the signature data types.
type SignatureDataInterface interface {
	fmt.Stringer

	// Verify returns nil if signedData was indeed signed by key pk, and
	// returns an appropriate error otherwise.
	Verify(pk crypto.PublicKey, signedData []byte) error
}

// SignatureRSAASA is RSAASA signature bytes.
type SignatureRSAASA []byte

// String implements fmt.Stringer
func (s SignatureRSAASA) String() string {
	return fmt.Sprintf("0x%X", []byte(s))
}

// Verify implements SignatureDataInterface.
func (s SignatureRSAASA) Verify(pkIface crypto.PublicKey, signedData []byte) error {
	pk, ok := pkIface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected public key of type %T, but received %T", pk, pkIface)
	}

	h := sha256.New()
	h.Write(signedData)
	hash := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, hash, s)
	if err != nil {
		return fmt.Errorf("data was not signed by the key: %w", err)
	}

	return nil
}
