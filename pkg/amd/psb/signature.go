// Copyright 2023 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psb

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
)

// SignedBlob represents an object whose signature is guaranteed to be validated
type SignedBlob struct {
	signature  *Signature
	signedData []byte
}

// SignedData returns a buffer of signed data held by the SignedBlob object
func (b *SignedBlob) SignedData() []byte {
	return b.signedData
}

// Signature returns the signature of the blob
func (b *SignedBlob) Signature() *Signature {
	return b.signature
}

// NewSignedBlob creates a new signed blob object and validates its signature
func NewSignedBlob(signature []byte, signedData []byte, signingKey *Key) (*SignedBlob, error) {
	structuredKey, err := signingKey.Get()
	if err != nil {
		return nil, &SignatureCheckError{signingKey: signingKey, err: fmt.Errorf("could not get structured key data from key in signature object: %w", err)}
	}

	switch rsaKey := structuredKey.(type) {
	case *rsa.PublicKey:
		var (
			hashAlg crypto.Hash
			digest  []byte
		)
		switch size := rsaKey.Size(); size {
		case sha512.Size * 8:
			hashAlg = crypto.SHA384
			hash := sha512.New384()
			hash.Write(signedData)
			digest = hash.Sum(nil)
		case sha256.Size * 8:
			hashAlg = crypto.SHA256
			hash := sha256.New()
			hash.Write(signedData)
			digest = hash.Sum(nil)
		default:
			return nil, fmt.Errorf("signature validation for RSA key with size != 4096/2048 bit (%d) is not supported", size)
		}

		if err := rsa.VerifyPSS(rsaKey, hashAlg, digest, signature, nil); err != nil {
			return nil, &SignatureCheckError{signingKey: signingKey, err: err}
		}
		signature := NewSignature(signature, signingKey)
		return &SignedBlob{signedData: signedData, signature: &signature}, nil
	}
	return nil, fmt.Errorf("signature validation with key type != RSA is not supported")
}

// NewMultiKeySignedBlob validates the signature of a blob against multiple possible keys stored in a KeySet,
// returning the key which validates the signature of the blob
func NewMultiKeySignedBlob(signature []byte, signedData []byte, keySet KeySet) (*SignedBlob, *Key, error) {
	allKeyIDs := keySet.AllKeyIDs()
	for _, keyID := range allKeyIDs {
		key := keySet.GetKey(keyID)
		if key == nil {
			return nil, nil, fmt.Errorf("KeySet is inconsistent, KeyID %s was returned but corresponding key is not present", keyID.Hex())
		}

		blob, err := NewSignedBlob(signature, signedData, key)
		if err == nil {
			return blob, key, nil
		}
	}

	return nil, nil, fmt.Errorf("cannot validate signed blob with any of the %d keys available (%s)", len(allKeyIDs), allKeyIDs.String())
}

// Signature represents the raw signature bytes of a blob
type Signature struct {
	signature  []byte
	signingKey *Key
}

// String returns a string representation of the signature
func (s *Signature) String() string {
	keyID := s.signingKey.data.KeyID
	var str strings.Builder
	fmt.Fprintf(&str, "KeyID: %s\n", keyID.Hex())
	fmt.Fprintf(&str, "Signature: 0x%x\n", s.signature)
	return str.String()
}

// SigningKey returns the signing key associated to the signature
func (s *Signature) SigningKey() *Key {
	return s.signingKey
}

// NewSignature creates a new signature object
func NewSignature(signature []byte, signingKey *Key) Signature {
	return Signature{signature: signature, signingKey: signingKey}
}

// SignatureValidationResult represents the result of a signature validate
type SignatureValidationResult struct {
	signingKey    *Key
	signedElement string
	err           error
}

// String returns a string representation of the signature validation result
func (v *SignatureValidationResult) String() string {

	var str strings.Builder
	fmt.Fprintf(&str, "Signed element: %s\n", v.signedElement)
	if v.signingKey != nil {
		keyID := v.signingKey.data.KeyID
		fmt.Fprintf(&str, "Signing key ID: 0x%s\n", keyID.Hex())
	} else {
		fmt.Fprintf(&str, "Signing key ID: UNKNOWN\n")
	}
	if v.err != nil {
		fmt.Fprintf(&str, "Signature: FAIL (%s)\n", v.err.Error())
	} else {
		fmt.Fprintf(&str, "Signature: OK\n")
	}
	return str.String()
}

// SigningKey returns a key that was used to validate the signature
func (v *SignatureValidationResult) SigningKey() *Key {
	return v.signingKey
}

// Error returns a signature verification error if any
func (v *SignatureValidationResult) Error() error {
	return v.err
}
