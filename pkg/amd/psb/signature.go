package psb

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"strings"
)

// SignedBlob is an interface implemented by signed blobs in AMD firmware
type SignedBlob interface {
	// GetSignature returns signature information and an implementation of SignedData interface.
	// It takes a KeyDB as argument, as the content of the KeyDB might determines the size of the
	// signature.
	GetSignature(keydb *KeyDatabase) (*Signature, *Key, SignedData, error)
}

// SignedData is an interface implemented by signed data which includes a header and raw data
type SignedData interface {
	DataWithHeader() []byte
	DataWithoutHeader() []byte
}

// PSBBinarySignedData represents signed data extracted from a PSP Table entry, including header and body
type PSBBinarySignedData struct {
	signedData []byte
}

// DataWithHeader returns the whole signed data buffer, including header and body
func (d *PSBBinarySignedData) DataWithHeader() []byte {
	return d.signedData
}

// DataWithoutHeader returns the data help by the PSP binary without header
func (d *PSBBinarySignedData) DataWithoutHeader() []byte {
	return d.signedData[pspHeaderSize:]
}

// NewPSBBinarySignedData creates a new signed data object for PSP binary
func NewPSBBinarySignedData(signedData []byte) (SignedData, error) {
	if len(signedData) <= pspHeaderSize {
		return nil, fmt.Errorf("PSP binary cannot be smaller than or equal to header size")
	}
	return &PSBBinarySignedData{signedData: signedData}, nil
}

// Signature represents the raw signature bytes of a blob
type Signature struct {
	keyID     KeyID
	signature []byte
}

// Validate validates the signature against the data and key provided
func (s Signature) Validate(data SignedData, key *Key) error {

	structuredKey, err := key.Get()
	if err != nil {
		return fmt.Errorf("could not get structured key data from raw key: %w", err)
	}

	switch rsaKey := structuredKey.(type) {
	case *rsa.PublicKey:
		switch size := rsaKey.Size(); size {
		case 512:
			hashAlg := crypto.SHA384
			hash := sha512.New384()
			hash.Write(data.DataWithHeader())
			return rsa.VerifyPSS(rsaKey, hashAlg, hash.Sum(nil), s.signature, nil)
		default:
			return fmt.Errorf("signature validation for RSA key with size != 4096 bit (%d) is not supported", size)
		}

	default:
		return fmt.Errorf("signature validation with key type != RSA is not supported")
	}

	return fmt.Errorf("coult not validate signature: unexpected configuration")
}

// String returns a string representation of the signature
func (s *Signature) String() string {
	var str strings.Builder
	fmt.Fprintf(&str, "KeyID: %s\n", s.keyID.Hex())
	fmt.Fprintf(&str, "Signature: 0x%x\n", s.signature)
	return str.String()
}

// KeyID returns the KeyID which signed the data
func (s *Signature) KeyID() KeyID {
	return s.keyID
}

// NewSignature creates a new signature object
func NewSignature(signature []byte, keyID KeyID) Signature {
	return Signature{signature: signature, keyID: keyID}
}

// SignatureValidationResult represents the result of a signature validate
type SignatureValidationResult struct {
	signedElement string
	signingKey    KeyID
	err           error
}

// String returns a string representation of the signature validation result
func (v *SignatureValidationResult) String() string {
	var str strings.Builder
	fmt.Fprintf(&str, "Signed element: %s\n", v.signedElement)
	fmt.Fprintf(&str, "Signing key ID: 0x%s\n", v.signingKey.Hex())
	if v.err != nil {
		fmt.Fprintf(&str, "Signature: FAIL (%s)\n", v.err.Error())
	} else {
		fmt.Fprintf(&str, "Signature: OK\n")
	}
	return str.String()
}
