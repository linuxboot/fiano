// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"strings"
	"testing"
)

func TestAlgorithmIsNull(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		alg  Algorithm
		want bool
	}{
		"unknown": {alg: AlgUnknown, want: true},
		"null":    {alg: AlgNull, want: true},
		"sha256":  {alg: AlgSHA256, want: false},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tt.alg.IsNull(); got != tt.want {
				t.Errorf("Algorithm(%v).IsNull() = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestAlgorithmHash(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		alg      Algorithm
		wantSize int
		wantErr  bool
	}{
		"sha1":     {alg: AlgSHA1, wantSize: 20},
		"sha256":   {alg: AlgSHA256, wantSize: 32},
		"sha384":   {alg: AlgSHA384, wantSize: 48},
		"sha512":   {alg: AlgSHA512, wantSize: 64},
		"sm3":      {alg: AlgSM3, wantSize: 32},
		"non_hash": {alg: AlgRSA, wantErr: true},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, err := tt.alg.Hash()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Algorithm(%v).Hash() error = nil, want non-nil", tt.alg)
				}
				return
			}

			if err != nil {
				t.Fatalf("Algorithm(%v).Hash() error = %v, want nil", tt.alg, err)
			}
			if got := h.Size(); got != tt.wantSize {
				t.Errorf("Algorithm(%v).Hash().Size() = %d, want %d", tt.alg, got, tt.wantSize)
			}
		})
	}
}

func TestAlgorithmString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		alg  Algorithm
		want string
	}{
		"unknown_alg": {alg: AlgUnknown, want: "AlgUnknown"},
		"rsa":         {alg: AlgRSA, want: "RSA"},
		"sha1":        {alg: AlgSHA1, want: "SHA1"},
		"sha256":      {alg: AlgSHA256, want: "SHA256"},
		"sha384":      {alg: AlgSHA384, want: "SHA384"},
		"sha512":      {alg: AlgSHA512, want: "SHA512"},
		"sm3":         {alg: AlgSM3, want: "SM3"},
		"alg_null":    {alg: AlgNull, want: "AlgNull"},
		"rsassa":      {alg: AlgRSASSA, want: "RSASSA"},
		"rsapss":      {alg: AlgRSAPSS, want: "RSAPSS"},
		"ecdsa":       {alg: AlgECDSA, want: "ECDSA"},
		"ecc":         {alg: AlgECC, want: "ECC"},
		"sm2":         {alg: AlgSM2, want: "SM2"},
		"fallback":    {alg: Algorithm(0xFFFF), want: "Alg?<65535>"},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := tt.alg.String(); got != tt.want {
				t.Errorf("Algorithm(%d).String() = %q, want %q", tt.alg, got, tt.want)
			}
		})
	}
}

func TestGetAlgFromString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in      string
		want    Algorithm
		wantErr bool
	}{
		"algunknown": {in: "AlgUnknown", want: AlgUnknown},
		"rsa":        {in: "rsa", want: AlgRSA},
		"sha1":       {in: "SHA1", want: AlgSHA1},
		"sha256":     {in: "sha256", want: AlgSHA256},
		"sha384":     {in: "SHA384", want: AlgSHA384},
		"sm3":        {in: "sm3", want: AlgSM3},
		"algnull":    {in: "AlgNull", want: AlgNull},
		"rsassa":     {in: "RSASSA", want: AlgRSASSA},
		"rsapss":     {in: "rsapss", want: AlgRSAPSS},
		"ecdsa":      {in: "ECDSA", want: AlgECDSA},
		"ecc":        {in: "ecc", want: AlgECC},
		"sm2":        {in: "SM2", want: AlgSM2},
		"bad":        {in: "invalid-algo", want: AlgNull, wantErr: true},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := GetAlgFromString(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetAlgFromString(%q) error = nil, want non-nil", tt.in)
				}
			} else if err != nil {
				t.Fatalf("GetAlgFromString(%q) error = %v, want nil", tt.in, err)
			}

			if got != tt.want {
				t.Errorf("GetAlgFromString(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestAlgorithmPrettyStringTotalSizeAndRW(t *testing.T) {
	t.Parallel()

	a := AlgSHA256
	if got, want := a.PrettyString(0, true), a.String(); got != want {
		t.Errorf("Algorithm.PrettyString() = %q, want %q", got, want)
	}

	if got := a.TotalSize(); got != 2 {
		t.Errorf("Algorithm.TotalSize() = %d, want %d", got, 2)
	}

	var buf bytes.Buffer
	n, err := a.WriteTo(&buf)
	if err != nil {
		t.Fatalf("Algorithm.WriteTo() error = %v, want nil", err)
	}
	if n != int64(a.TotalSize()) {
		t.Errorf("Algorithm.WriteTo() bytes = %d, want %d", n, a.TotalSize())
	}

	var got Algorithm
	n, err = (&got).ReadFrom(&buf)
	if err != nil {
		t.Fatalf("Algorithm.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("Algorithm.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}
	if got != a {
		t.Errorf("Algorithm round-trip = %v, want %v", got, a)
	}

	_, err = (&got).ReadFrom(bytes.NewBuffer([]byte{0x01}))
	if err == nil {
		t.Errorf("Algorithm.ReadFrom(short input) error = nil, want non-nil")
	} else if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("Algorithm.ReadFrom(short input) error = %q, want to contain %q", err.Error(), "unexpected EOF")
	}
}
