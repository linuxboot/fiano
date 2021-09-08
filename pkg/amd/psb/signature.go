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
	GetSignature(keydb *KeyDatabase) (*Signature, SignedData, error)
}

// SignedData is an interface implemented by signed data which includes a header and raw data
type SignedData interface {
	DataWithHeader() []byte
	DataWithoutHeader() []byte
}

// PspBinarySignedData represents signed data extracted from a PSP Table entry, including header and body
type PspBinarySignedData struct {
	signedData []byte
}

// DataWithHeader returns the whole signed data buffer, including header and body
func (d *PspBinarySignedData) DataWithHeader() []byte {
	return d.signedData
}

// DataWithoutHeader returns the data help by the PSP binary without header
func (d *PspBinarySignedData) DataWithoutHeader() []byte {
	return d.signedData[pspHeaderSize:]
}

// NewPspBinarySignedData creates a new signed data object for PSP binary
func NewPspBinarySignedData(signedData []byte) (SignedData, error) {
	if len(signedData) <= pspHeaderSize {
		return nil, fmt.Errorf("PSP binary cannot be smaller than or equal to header size")
	}
	return &PspBinarySignedData{signedData: signedData}, nil
}

// Signature represents the raw signature bytes of a blob
type Signature struct {
	keyFingerprint string
	signature      []byte
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
	fmt.Fprintf(&str, "Key fingerprint: %s\n", s.keyFingerprint)
	fmt.Fprintf(&str, "Signature: 0x%x\n", s.signature)
	return str.String()
}

// NewSignature creates a new signature object
func NewSignature(signature []byte, keyFingerprint string) Signature {
	return Signature{signature: signature, keyFingerprint: keyFingerprint}
}
