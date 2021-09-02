package psb

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"strings"
)

// SignatureGetter is an interface implemented by signed blobs in AMD firmware
type SignatureGetter interface {
	// GetSignature returns signature information
	GetSignature() (*Signature, *SignedData, error)
}

// SignedData represents portion of data which is signed
type SignedData struct {
	signedData []byte
}

// Data returns the signed data buffer
func (d SignedData) Data() []byte {
	return d.signedData
}

// NewSignedData returns a new SignedData object
func NewSignedData(signedData []byte) SignedData {
	return SignedData{signedData: signedData}
}

// Signature represents the raw signature bytes of a blob
type Signature struct {
	keyFingerprint string
	signature      []byte
}

// Validate validates the signature against the data and key provided
func (s Signature) Validate(data *SignedData, key *Key) error {

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
			hash.Write(data.Data())
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
	fmt.Fprintf(&str, "Key fingerprint: %s\n", s.keyFingerprint)
	fmt.Fprintf(&str, "Signature: 0x%x\n", s.signature)
	return str.String()
}

// NewSignature creates a new signature object
func NewSignature(signature []byte, keyFingerprint string) Signature {
	return Signature{signature: signature, keyFingerprint: keyFingerprint}
}
