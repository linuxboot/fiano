// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func TestSignatureNewAndValidate(t *testing.T) {
	t.Parallel()

	s := NewSignature()
	if s == nil {
		t.Fatal("NewSignature() = nil, want non-nil")
	}
	if s.Version != 0x10 {
		t.Errorf("NewSignature().Version = 0x%x, want 0x10", s.Version)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("NewSignature().Validate() error = %v, want nil", err)
	}
}

func TestSignatureValidateRejectsInvalidVersion(t *testing.T) {
	t.Parallel()

	s := NewSignature()
	s.Version = 0

	if err := s.Validate(); err == nil {
		t.Errorf("Signature.Validate() error = nil, want non-nil")
	}
}

func TestSignatureSetSignatureByData(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sig           SignatureDataInterface
		hashAlgo      Algorithm
		wantSigScheme Algorithm
		wantHash      Algorithm
		wantSizeBits  uint16
	}{
		"rsassa_default_hash": {
			sig:           SignatureRSAASA([]byte{1, 2, 3, 4}),
			hashAlgo:      AlgUnknown,
			wantSigScheme: AlgRSASSA,
			wantHash:      AlgSHA256,
			wantSizeBits:  32,
		},
		"rsapss_default_hash": {
			sig:           SignatureRSAPSS([]byte{1, 2, 3, 4, 5, 6}),
			hashAlgo:      AlgUnknown,
			wantSigScheme: AlgRSAPSS,
			wantHash:      AlgSHA384,
			wantSizeBits:  48,
		},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := NewSignature()
			if err := s.SetSignatureByData(tt.sig, tt.hashAlgo); err != nil {
				t.Fatalf("Signature.SetSignatureByData() error = %v, want nil", err)
			}

			if s.SigScheme != tt.wantSigScheme {
				t.Errorf("Signature.SetSignatureByData() SigScheme = %v, want %v", s.SigScheme, tt.wantSigScheme)
			}
			if s.HashAlg != tt.wantHash {
				t.Errorf("Signature.SetSignatureByData() HashAlg = %v, want %v", s.HashAlg, tt.wantHash)
			}
			if got := s.KeySize.InBits(); got != tt.wantSizeBits {
				t.Errorf("Signature.SetSignatureByData() KeySize = %d, want %d", got, tt.wantSizeBits)
			}
		})
	}
}

func TestSignatureSetSignatureDataErrors(t *testing.T) {
	t.Parallel()

	s := NewSignature()

	if err := s.SetSignatureData(unsupportedSignatureData{}); err == nil {
		t.Errorf("Signature.SetSignatureData(unsupportedSignatureData{}) error = nil, want non-nil")
	}

	badLen := SignatureECDSA{R: big.NewInt(1), S: new(big.Int).Lsh(big.NewInt(1), 255)}
	if err := s.SetSignatureData(badLen); err == nil {
		t.Errorf("Signature.SetSignatureData(mismatched ECDSA components) error = nil, want non-nil")
	}

	badSize := SignatureECDSA{R: big.NewInt(1), S: big.NewInt(1)}
	if err := s.SetSignatureData(badSize); err == nil {
		t.Errorf("Signature.SetSignatureData(non-256/384 ECDSA components) error = nil, want non-nil")
	}
}

func TestSignatureSetFillAndParseDataWithRSA(t *testing.T) {
	key := genRSA(t, 2048)

	payload := []byte("signature-rsa")

	sSet := NewSignature()
	if err := sSet.SetSignature(AlgRSASSA, AlgSHA256, key, payload); err != nil {
		t.Fatalf("Signature.SetSignature() error = %v, want nil", err)
	}
	parsed, err := sSet.SignatureData()
	if err != nil {
		t.Fatalf("Signature.SignatureData() error = %v, want nil", err)
	}
	if err := parsed.Verify(&key.PublicKey, sSet.HashAlg, payload); err != nil {
		t.Errorf("SignatureData.Verify() error = %v, want nil", err)
	}

	sFill := NewSignature()
	if err := sFill.FillSignature(AlgRSASSA, &key.PublicKey, sSet.Data, AlgSHA256); err != nil {
		t.Fatalf("Signature.FillSignature() error = %v, want nil", err)
	}
	parsedFill, err := sFill.SignatureData()
	if err != nil {
		t.Fatalf("Signature.SignatureData() after FillSignature error = %v, want nil", err)
	}
	if err := parsedFill.Verify(&key.PublicKey, sFill.HashAlg, payload); err != nil {
		t.Errorf("SignatureData.Verify() after FillSignature error = %v, want nil", err)
	}
}

func TestSignatureDataByScheme(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sigScheme Algorithm
		data      []byte
		wantType  string
		wantErr   bool
		errSub    string
	}{
		"rsapss": {sigScheme: AlgRSAPSS, data: []byte{1, 2, 3}, wantType: "cbnt.SignatureRSAPSS"},
		"rsassa": {sigScheme: AlgRSASSA, data: []byte{4, 5, 6}, wantType: "cbnt.SignatureRSAASA"},
		"ecdsa_64": {
			sigScheme: AlgECDSA,
			data:      bytes.Repeat([]byte{0x11}, 64),
			wantType:  "cbnt.SignatureECDSA",
		},
		"sm2_96": {
			sigScheme: AlgSM2,
			data:      bytes.Repeat([]byte{0x22}, 96),
			wantType:  "cbnt.SignatureSM2",
		},
		"ecdsa_bad_len": {
			sigScheme: AlgECDSA,
			data:      []byte{1, 2, 3},
			wantErr:   true,
			errSub:    "invalid length",
		},
		"sm2_bad_len": {
			sigScheme: AlgSM2,
			data:      []byte{1, 2, 3},
			wantErr:   true,
			errSub:    "invalid length",
		},
		"unknown_scheme": {
			sigScheme: AlgSHA256,
			data:      []byte{1},
			wantErr:   true,
			errSub:    "unexpected signature scheme",
		},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := Signature{SigScheme: tt.sigScheme, Data: tt.data}
			got, err := s.SignatureData()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Signature.SignatureData(%v) error = nil, want non-nil", tt.sigScheme)
				} else if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Signature.SignatureData(%v) error = %q, want substring %q", tt.sigScheme, err.Error(), tt.errSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("Signature.SignatureData(%v) error = %v, want nil", tt.sigScheme, err)
			}
			if gotType := fmt.Sprintf("%T", got); gotType != tt.wantType {
				t.Errorf("Signature.SignatureData(%v) type = %s, want %s", tt.sigScheme, gotType, tt.wantType)
			}
		})
	}
}

func TestSignatureSetSignatureByDataAdditionalCases(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		sig           SignatureDataInterface
		hashAlgo      Algorithm
		wantSigScheme Algorithm
		wantHash      Algorithm
		wantKeyBits   uint16
		wantErr       bool
		errSub        string
	}{
		"ecdsa_default_hash": {
			sig:           SignatureECDSA{R: bigIntBits(256), S: bigIntBits(256)},
			hashAlgo:      AlgUnknown,
			wantSigScheme: AlgECDSA,
			wantHash:      AlgSHA512,
			wantKeyBits:   256,
		},
		"sm2_default_hash": {
			sig:           SignatureSM2{R: bigIntBits(256), S: bigIntBits(256)},
			hashAlgo:      AlgUnknown,
			wantSigScheme: AlgSM2,
			wantHash:      AlgSM3,
			wantKeyBits:   256,
		},
		"ecdsa_explicit_hash": {
			sig:           SignatureECDSA{R: bigIntBits(256), S: bigIntBits(256)},
			hashAlgo:      AlgSHA384,
			wantSigScheme: AlgECDSA,
			wantHash:      AlgSHA384,
			wantKeyBits:   256,
		},
		"unsupported_sig_type": {
			sig:     unsupportedSignatureData{},
			wantErr: true,
			errSub:  "unexpected signature type",
		},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := NewSignature()
			err := s.SetSignatureByData(tt.sig, tt.hashAlgo)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Signature.SetSignatureByData(%T) error = nil, want non-nil", tt.sig)
				} else if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Signature.SetSignatureByData(%T) error = %q, want substring %q", tt.sig, err.Error(), tt.errSub)
				}
				return
			}

			if err != nil {
				t.Fatalf("Signature.SetSignatureByData(%T) error = %v, want nil", tt.sig, err)
			}
			if s.SigScheme != tt.wantSigScheme {
				t.Errorf("Signature.SetSignatureByData(%T) SigScheme = %v, want %v", tt.sig, s.SigScheme, tt.wantSigScheme)
			}
			if s.HashAlg != tt.wantHash {
				t.Errorf("Signature.SetSignatureByData(%T) HashAlg = %v, want %v", tt.sig, s.HashAlg, tt.wantHash)
			}
			if got := s.KeySize.InBits(); got != tt.wantKeyBits {
				t.Errorf("Signature.SetSignatureByData(%T) KeySize bits = %d, want %d", tt.sig, got, tt.wantKeyBits)
			}
		})
	}
}

func TestNewSignatureDataAndNewSignatureByData(t *testing.T) {
	rsaKey := genRSA(t, 2048)
	ecdsaKey := genECDSA(t)
	data := []byte("signature-data")

	t.Run("NewSignatureData", func(t *testing.T) {
		tests := map[string]struct {
			signAlgo Algorithm
			privKey  crypto.Signer
			wantType string
			wantErr  bool
			errSub   string
		}{
			"auto_detect_rsa": {
				signAlgo: 0,
				privKey:  rsaKey,
				wantErr:  true,
				errSub:   "is not implemented",
			},
			"explicit_rsassa": {
				signAlgo: AlgRSASSA,
				privKey:  rsaKey,
				wantType: "cbnt.SignatureRSAASA",
			},
			"ecdsa_wrong_key_type": {
				signAlgo: AlgECDSA,
				privKey:  rsaKey,
				wantErr:  true,
				errSub:   "expected private ECDSA key",
			},
			"unsupported_algo": {
				signAlgo: AlgSHA1,
				privKey:  rsaKey,
				wantErr:  true,
				errSub:   "is not implemented",
			},
		}

		for name, tt := range tests {
			name := name
			tt := tt
			t.Run(name, func(t *testing.T) {
				sig, err := NewSignatureData(tt.signAlgo, tt.privKey, data)
				if tt.wantErr {
					if err == nil {
						t.Errorf("NewSignatureData(%v, %T) error = nil, want non-nil", tt.signAlgo, tt.privKey)
					} else if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
						t.Errorf("NewSignatureData(%v, %T) error = %q, want substring %q", tt.signAlgo, tt.privKey, err.Error(), tt.errSub)
					}
					return
				}

				if err != nil {
					t.Fatalf("NewSignatureData(%v, %T) error = %v, want nil", tt.signAlgo, tt.privKey, err)
				}
				if gotType := fmt.Sprintf("%T", sig); gotType != tt.wantType {
					t.Errorf("NewSignatureData(%v, %T) type = %s, want %s", tt.signAlgo, tt.privKey, gotType, tt.wantType)
				}
			})
		}
	})

	t.Run("NewSignatureByData", func(t *testing.T) {
		rawECDSA := append(bytes.Repeat([]byte{0xA5}, 32), bytes.Repeat([]byte{0x5A}, 32)...)

		tests := map[string]struct {
			signAlgo Algorithm
			pubKey   crypto.PublicKey
			input    []byte
			wantType string
			wantErr  bool
			errSub   string
		}{
			"auto_detect_rsa": {
				signAlgo: 0,
				pubKey:   &rsaKey.PublicKey,
				input:    []byte{1, 2, 3},
				wantType: "cbnt.SignatureRSAASA",
			},
			"auto_detect_ecdsa": {
				signAlgo: 0,
				pubKey:   &ecdsaKey.PublicKey,
				input:    rawECDSA,
				wantType: "cbnt.SignatureECDSA",
			},
			"explicit_pss": {
				signAlgo: AlgRSAPSS,
				pubKey:   &rsaKey.PublicKey,
				input:    []byte{9, 8, 7},
				wantType: "cbnt.SignatureRSAPSS",
			},
			"unsupported_algo": {
				signAlgo: AlgSHA1,
				pubKey:   &rsaKey.PublicKey,
				input:    []byte{1},
				wantErr:  true,
				errSub:   "is not implemented",
			},
		}

		for name, tt := range tests {
			name := name
			tt := tt
			t.Run(name, func(t *testing.T) {
				sig, err := NewSignatureByData(tt.signAlgo, tt.pubKey, tt.input)
				if tt.wantErr {
					if err == nil {
						t.Errorf("NewSignatureByData(%v, %T) error = nil, want non-nil", tt.signAlgo, tt.pubKey)
					} else if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
						t.Errorf("NewSignatureByData(%v, %T) error = %q, want substring %q", tt.signAlgo, tt.pubKey, err.Error(), tt.errSub)
					}
					return
				}

				if err != nil {
					t.Fatalf("NewSignatureByData(%v, %T) error = %v, want nil", tt.signAlgo, tt.pubKey, err)
				}
				if gotType := fmt.Sprintf("%T", sig); gotType != tt.wantType {
					t.Errorf("NewSignatureByData(%v, %T) type = %s, want %s", tt.signAlgo, tt.pubKey, gotType, tt.wantType)
				}
			})
		}
	})
}

func TestSignatureReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	want := &Signature{
		SigScheme: AlgRSASSA,
		Version:   0x10,
		HashAlg:   AlgSHA256,
		Data:      []byte{0x10, 0x11, 0x12, 0x13},
	}
	want.KeySize.SetInBytes(uint16(len(want.Data)))

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("Signature.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("Signature.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got Signature
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("Signature.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("Signature.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.SigScheme != want.SigScheme {
		t.Errorf("Signature round-trip SigScheme = %v, want %v", got.SigScheme, want.SigScheme)
	}
	if got.KeySize != want.KeySize {
		t.Errorf("Signature round-trip KeySize = %v, want %v", got.KeySize, want.KeySize)
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Errorf("Signature round-trip Data = %v, want %v", got.Data, want.Data)
	}
}

func TestSignatureMethods(t *testing.T) {
	t.Parallel()

	s := NewSignature()
	if _, err := s.SizeOf(99); err == nil {
		t.Errorf("Signature.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := s.OffsetOf(99); err == nil {
		t.Errorf("Signature.OffsetOf(99) error = nil, want non-nil")
	}

	if got := len(s.Layout()); got != 5 {
		t.Errorf("len(Signature.Layout()) = %d, want %d", got, 5)
	}

	var nilSig *Signature
	if got := nilSig.TotalSize(); got != 0 {
		t.Errorf("(*Signature)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := s.PrettyString(0, true)
	if !strings.Contains(pretty, "Signature") {
		t.Errorf("Signature.PrettyString() = %q, want to contain %q", pretty, "Signature")
	}
}

type unsupportedSignatureData struct{}

func (unsupportedSignatureData) String() string { return "unsupported" }

func (unsupportedSignatureData) Verify(pkIface crypto.PublicKey, hashAlgo Algorithm, signedData []byte) error {
	return nil
}

func genRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d) error = %v, want nil", bits, err)
	}

	return key
}

func genECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P256) error = %v, want nil", err)
	}

	return key
}

func bigIntBits(bits int) *big.Int {
	b := make([]byte, bits/8)
	b[0] = 0x80
	return new(big.Int).SetBytes(b)
}
