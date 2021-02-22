//go:generate manifestcodegen

package manifest

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	// RandReader exports the rand.Reader
	RandReader = rand.Reader
)

// Signature exports the Signature structure
type Signature struct {
	SigScheme Algorithm `json:"sig_scheme"`
	Version   uint8     `require:"0x10" json:"sig_version,omitempty"`
	KeySize   BitSize   `json:"sig_keysize,omitempty"`
	HashAlg   Algorithm `json:"sig_hashAlg"`
	Data      []byte    `countValue:"KeySize.InBytes()" prettyValue:"dataPrettyValue()" json:"sig_data"`
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
	case AlgRSAPSS:
		return SignatureRSAPSS(m.Data), nil
	case AlgRSASSA:
		return SignatureRSAASA(m.Data), nil
	case AlgECDSA:
		if len(m.Data) != 64 && len(m.Data) != 96 {
			return nil, fmt.Errorf("invalid length of the signature data: %d (expected 64 or 96)", len(m.Data))
		}
		return SignatureECDSA{
			R: new(big.Int).SetBytes(reverseBytes(m.Data[:len(m.Data)/2])),
			S: new(big.Int).SetBytes(reverseBytes(m.Data[len(m.Data)/2:])),
		}, nil
	case AlgSM2:
		if len(m.Data) != 64 && len(m.Data) != 96 {
			return nil, fmt.Errorf("invalid length of the signature data: %d (expected 64 or 96)", len(m.Data))
		}
		return SignatureSM2{
			R: new(big.Int).SetBytes(reverseBytes(m.Data[:len(m.Data)/2])),
			S: new(big.Int).SetBytes(reverseBytes(m.Data[len(m.Data)/2:])),
		}, nil
	}

	return nil, fmt.Errorf("unexpected signature scheme: %s", m.SigScheme)
}

// SetSignatureByData sets all the fields of the structure Signature by
// accepting one of these types as the input argument `sig`:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (m *Signature) SetSignatureByData(sig SignatureDataInterface) error {
	err := m.SetSignatureData(sig)
	if err != nil {
		return err
	}

	switch sig := sig.(type) {
	case SignatureRSAPSS:
		m.SigScheme = AlgRSA
		m.HashAlg = AlgSHA256
		m.KeySize.SetInBytes(uint16(len(m.Data)))
	case SignatureRSAASA:
		m.SigScheme = AlgRSA
		m.HashAlg = AlgSHA256
		m.KeySize.SetInBytes(uint16(len(m.Data)))
	case SignatureECDSA:
		m.SigScheme = AlgECDSA
		m.HashAlg = AlgSHA256
		m.KeySize.SetInBits(uint16(sig.R.BitLen()))
	case SignatureSM2:
		m.SigScheme = AlgSM2
		m.HashAlg = AlgSM3_256
		m.KeySize.SetInBits(uint16(sig.R.BitLen()))
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
	case SignatureRSAPSS:
		m.Data = sig
	case SignatureRSAASA:
		m.Data = sig
	case SignatureECDSA, SignatureSM2:
		var r, s *big.Int
		switch sig := sig.(type) {
		case SignatureECDSA:
			r, s = sig.R, sig.S
		case SignatureSM2:
			r, s = sig.R, sig.S
		default:
			return fmt.Errorf("internal error")
		}
		if r.BitLen() != s.BitLen() {
			return fmt.Errorf("the length of component R (%d) is not equal to the length of component S (%d)", r.BitLen(), s.BitLen())
		}
		if r.BitLen() != 256 && r.BitLen() != 384 {
			return fmt.Errorf("component R (or S) size should be 256 or 384 bites (not %d)", r.BitLen())
		}
		m.Data = make([]byte, r.BitLen()/8+s.BitLen()/8)
		copy(m.Data[:], reverseBytes(r.Bytes()))
		copy(m.Data[r.BitLen()/8:], reverseBytes(s.Bytes()))
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
	signData, err := NewSignatureData(signAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}

	err = m.SetSignatureByData(signData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}
