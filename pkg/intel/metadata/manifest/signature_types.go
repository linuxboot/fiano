// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

var sm2UID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

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
		switch k := privKey.(type) {
		case *rsa.PrivateKey:
			switch k.Size() {
			case 2048:
				signAlgo = AlgRSASSA
			case 3072:
				signAlgo = AlgRSAPSS
			}
		case *ecdsa.PrivateKey:
			signAlgo = AlgECDSA
		case *sm2.PrivateKey:
			signAlgo = AlgSM2
		}
	}
	switch signAlgo {
	case AlgRSAPSS:
		rsaPrivateKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected private RSA key (type %T), but received %T", rsaPrivateKey, privKey)
		}
		h := sha512.New384()
		_, _ = h.Write(signedData)
		bpmHash := h.Sum(nil)

		pss := rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA384,
		}
		data, err := rsa.SignPSS(RandReader, rsaPrivateKey, crypto.SHA384, bpmHash, &pss)
		if err != nil {
			return nil, fmt.Errorf("unable to sign with RSAPSS the data: %w", err)
		}
		return SignatureRSAPSS(data), nil
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
	case AlgECDSA:
		eccPrivateKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected private ECDSA key (type %T), but received %T", eccPrivateKey, privKey)
		}
		var data SignatureECDSA
		var err error
		data.R, data.S, err = ecdsa.Sign(RandReader, eccPrivateKey, signedData)
		if err != nil {
			return nil, fmt.Errorf("unable to sign with ECDSA the data: %w", err)
		}
		return data, nil
	case AlgSM2:
		eccPrivateKey, ok := privKey.(*sm2.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected private SM2 key (type %T), but received %T", eccPrivateKey, privKey)
		}
		var data SignatureSM2
		var err error
		data.R, data.S, err = sm2.Sm2Sign(eccPrivateKey, signedData, sm2UID, RandReader)
		if err != nil {
			return nil, fmt.Errorf("unable to sign with SM2 the data: %w", err)
		}
		return data, nil
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
		case *ecdsa.PublicKey:
			signAlgo = AlgECDSA
		case *sm2.PublicKey:
			signAlgo = AlgSM2
		}
	}
	switch signAlgo {
	case AlgRSAPSS:
		return SignatureRSAPSS(signedData), nil
	case AlgRSASSA:
		return SignatureRSAASA(signedData), nil
	case AlgECDSA:
		return SignatureECDSA{
			R: new(big.Int).SetBytes(reverseBytes(signedData[:len(signedData)/2])),
			S: new(big.Int).SetBytes(reverseBytes(signedData[len(signedData)/2:])),
		}, nil
	case AlgSM2:
		return SignatureSM2{
			R: new(big.Int).SetBytes(reverseBytes(signedData[:len(signedData)/2])),
			S: new(big.Int).SetBytes(reverseBytes(signedData[len(signedData)/2:])),
		}, nil
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

// SignatureRSAPSS is RSAPSS signature bytes.
type SignatureRSAPSS []byte

// String implements fmt.Stringer
func (s SignatureRSAPSS) String() string {
	return fmt.Sprintf("0x%X", []byte(s))
}

// Verify implements SignatureDataInterface.
func (s SignatureRSAPSS) Verify(pkIface crypto.PublicKey, signedData []byte) error {
	pk, ok := pkIface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected public key of type %T, but received %T", pk, pkIface)
	}
	h := sha256.New()
	if _, err := h.Write(signedData); err != nil {
		return fmt.Errorf("unable to hash the data: %w", err)
	}
	hash := h.Sum(nil)

	pss := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}
	err := rsa.VerifyPSS(pk, crypto.SHA256, hash, s, &pss)
	if err != nil {
		return fmt.Errorf("signature does not correspond to the pub key: %w", err)
	}
	return nil
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
	if _, err := h.Write(signedData); err != nil {
		return fmt.Errorf("unable to hash the data: %w", err)
	}
	hash := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, hash, s)
	if err != nil {
		return fmt.Errorf("signature does not correspond to the pub key: %w", err)
	}

	return nil
}

// SignatureECDSA is a structure with components of an ECDSA signature.
type SignatureECDSA struct {
	// R is the R component of the signature.
	R *big.Int
	// S is the S component of the signature.
	S *big.Int
}

// String implements fmt.Stringer
func (s SignatureECDSA) String() string {
	return fmt.Sprintf("{R: 0x%X, S: 0x%X}", s.R, s.S)
}

// Verify implements SignatureDataInterface.
func (s SignatureECDSA) Verify(pkIface crypto.PublicKey, signedData []byte) error {
	return fmt.Errorf("support of ECDSA signatures is not implemented, yet")
}

// SignatureSM2 is a structure with components of an SM2 signature.
type SignatureSM2 struct {
	// R is the R component of the signature.
	R *big.Int
	// S is the S component of the signature.
	S *big.Int
}

// String implements fmt.Stringer
func (s SignatureSM2) String() string {
	return fmt.Sprintf("{R: 0x%X, S: 0x%X}", s.R, s.S)
}

// Verify implements SignatureDataInterface.
func (s SignatureSM2) Verify(pkIface crypto.PublicKey, signedData []byte) error {
	return fmt.Errorf("support of SM2 signatures is not implemented, yet")
}
