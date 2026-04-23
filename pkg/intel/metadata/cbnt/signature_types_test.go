// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func TestSignatureRSAStringAndVerify(t *testing.T) {
	tests := []struct {
		name      string
		buildFunc func(*testing.T, *rsa.PrivateKey, []byte) ([]byte, SignatureDataInterface)
		okHash    Algorithm
		badHash   Algorithm
	}{
		{
			name: "RSAPSS",
			buildFunc: func(t *testing.T, key *rsa.PrivateKey, data []byte) ([]byte, SignatureDataInterface) {
				t.Helper()
				h := sha512.New384()
				if _, err := h.Write(data); err != nil {
					t.Fatalf("hash.Write() error = %v, want nil", err)
				}
				digest := h.Sum(nil)
				rawSig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA384, digest, &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       crypto.SHA384,
				})
				if err != nil {
					t.Fatalf("rsa.SignPSS() error = %v, want nil", err)
				}
				return rawSig, SignatureRSAPSS(rawSig)
			},
			okHash:  AlgSHA384,
			badHash: AlgSHA512,
		},
		{
			name: "RSAASA",
			buildFunc: func(t *testing.T, key *rsa.PrivateKey, data []byte) ([]byte, SignatureDataInterface) {
				t.Helper()
				h := sha256.New()
				if _, err := h.Write(data); err != nil {
					t.Fatalf("hash.Write() error = %v, want nil", err)
				}
				digest := h.Sum(nil)
				rawSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
				if err != nil {
					t.Fatalf("rsa.SignPKCS1v15() error = %v, want nil", err)
				}
				return rawSig, SignatureRSAASA(rawSig)
			},
			okHash:  AlgSHA256,
			badHash: AlgSHA512,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
			}

			wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey() error = %v, want nil", err)
			}

			data := []byte(strings.ToLower(tt.name) + "-signature-data")
			rawSig, sig := tt.buildFunc(t, key, data)

			if got, want := sig.String(), fmt.Sprintf("0x%X", rawSig); got != want {
				t.Errorf("%s.String() = %q, want %q", tt.name, got, want)
			}

			verifyTests := []struct {
				name    string
				pk      crypto.PublicKey
				hash    Algorithm
				msg     []byte
				wantErr bool
			}{
				{name: "valid", pk: &key.PublicKey, hash: tt.okHash, msg: data, wantErr: false},
				{name: "unsupported_hash", pk: &key.PublicKey, hash: tt.badHash, msg: data, wantErr: true},
				{name: "wrong_key_type", pk: &wrongKey.PublicKey, hash: tt.okHash, msg: data, wantErr: true},
				{name: "tampered_data", pk: &key.PublicKey, hash: tt.okHash, msg: []byte("tampered"), wantErr: true},
			}

			for _, vt := range verifyTests {
				vt := vt
				t.Run(vt.name, func(t *testing.T) {
					err := sig.Verify(vt.pk, vt.hash, vt.msg)
					if vt.wantErr {
						if err == nil {
							t.Errorf("%s.Verify(%s) error = nil, want non-nil", tt.name, vt.name)
						}
					} else if err != nil {
						t.Errorf("%s.Verify(%s) error = %v, want nil", tt.name, vt.name, err)
					}
				})
			}
		})
	}
}

func TestSignatureNonRSAStringAndVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sig          SignatureDataInterface
		hash         Algorithm
		wantString   string
		errSubstring string
	}{
		{
			name:         "ECDSA",
			sig:          SignatureECDSA{R: big.NewInt(0x12), S: big.NewInt(0xAB)},
			hash:         AlgSHA256,
			wantString:   "{R: 0x12, S: 0xAB}",
			errSubstring: "not implemented",
		},
		{
			name:         "SM2",
			sig:          SignatureSM2{R: big.NewInt(0x34), S: big.NewInt(0xCD)},
			hash:         AlgSM3,
			wantString:   "{R: 0x34, S: 0xCD}",
			errSubstring: "not implemented",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.sig.String(); got != tt.wantString {
				t.Errorf("%s.String() = %q, want %q", tt.name, got, tt.wantString)
			}

			err := tt.sig.Verify(nil, tt.hash, []byte("data"))
			if err == nil {
				t.Fatalf("%s.Verify() error = nil, want non-nil", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errSubstring) {
				t.Errorf("%s.Verify() error = %q, want substring %q", tt.name, err.Error(), tt.errSubstring)
			}
		})
	}
}
