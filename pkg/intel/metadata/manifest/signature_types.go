package manifest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// NewSignatureData returns an implementation of SignatureDataInterface,
// accordingly to signAlgo, privKey and signedData.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func NewSignatureData(
	signAlgo tpm2.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) (SignatureDataInterface, error) {
	if signAlgo == 0 {
		// auto-detect the sign algorithm, based on the provided signing key
		switch privKey.(type) {
		case *rsa.PrivateKey:
			signAlgo = tpm2.AlgRSASSA
		case *ecdsa.PrivateKey:
			signAlgo = tpm2.AlgECDSA
		}
	}

	switch signAlgo {
	case tpm2.AlgRSASSA:
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

	case tpm2.AlgECDSA:
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
