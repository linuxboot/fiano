// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestKeySignatureNew(t *testing.T) {
	t.Parallel()

	ks := NewKeySignature()
	if ks == nil {
		t.Fatal("NewKeySignature() = nil, want non-nil")
	}
	if ks.Version != 0x10 {
		t.Errorf("NewKeySignature().Version = 0x%x, want 0x10", ks.Version)
	}
	if ks.Key.Version != 0x10 {
		t.Errorf("NewKeySignature().Key.Version = 0x%x, want 0x10", ks.Key.Version)
	}
	if ks.Signature.Version != 0x10 {
		t.Errorf("NewKeySignature().Signature.Version = 0x%x, want 0x10", ks.Signature.Version)
	}
	if err := ks.Validate(); err != nil {
		t.Errorf("NewKeySignature().Validate() error = %v, want nil", err)
	}
}

func TestKeySignatureSetSignatureAuto(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
	}

	payload := []byte("key-signature-auto")
	ks := NewKeySignature()
	if err := ks.SetSignatureAuto(key, payload); err == nil {
		t.Errorf("KeySignature.SetSignatureAuto() error = nil, want non-nil")
	}
}

func TestKeySignatureSetSignatureAndFillSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
	}

	payload := []byte("key-signature-manual")

	ksSet := NewKeySignature()
	if err := ksSet.SetSignature(AlgRSASSA, AlgSHA256, key, payload); err != nil {
		t.Fatalf("KeySignature.SetSignature() error = %v, want nil", err)
	}
	if err := ksSet.Verify(payload); err != nil {
		t.Errorf("KeySignature.Verify() after SetSignature error = %v, want nil", err)
	}

	sigData, err := NewSignatureData(AlgRSASSA, key, payload)
	if err != nil {
		t.Fatalf("NewSignatureData() error = %v, want nil", err)
	}
	rawSig, ok := sigData.(SignatureRSAASA)
	if !ok {
		t.Fatalf("NewSignatureData() type = %T, want %T", sigData, SignatureRSAASA(nil))
	}

	ksFill := NewKeySignature()
	if err := ksFill.FillSignature(AlgRSASSA, &key.PublicKey, []byte(rawSig), AlgSHA256); err != nil {
		t.Fatalf("KeySignature.FillSignature() error = %v, want nil", err)
	}
	if err := ksFill.Verify(payload); err != nil {
		t.Errorf("KeySignature.Verify() after FillSignature error = %v, want nil", err)
	}
}

func TestKeySignatureReadWriteRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
	}

	want := NewKeySignature()
	if err := want.SetSignature(AlgRSASSA, AlgSHA256, key, []byte("round-trip")); err != nil {
		t.Fatalf("KeySignature.SetSignature() error = %v, want nil", err)
	}

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("KeySignature.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("KeySignature.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got KeySignature
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("KeySignature.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("KeySignature.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.Version != want.Version {
		t.Errorf("KeySignature round-trip Version = 0x%x, want 0x%x", got.Version, want.Version)
	}
	if got.Key.KeyAlg != want.Key.KeyAlg {
		t.Errorf("KeySignature round-trip KeyAlg = %v, want %v", got.Key.KeyAlg, want.Key.KeyAlg)
	}
	if got.Signature.SigScheme != want.Signature.SigScheme {
		t.Errorf("KeySignature round-trip SigScheme = %v, want %v", got.Signature.SigScheme, want.Signature.SigScheme)
	}
}

func TestKeySignatureMethods(t *testing.T) {
	t.Parallel()

	ks := NewKeySignature()
	if _, err := ks.SizeOf(99); err == nil {
		t.Errorf("KeySignature.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := ks.OffsetOf(99); err == nil {
		t.Errorf("KeySignature.OffsetOf(99) error = nil, want non-nil")
	}

	if got := len(ks.Layout()); got != 3 {
		t.Errorf("len(KeySignature.Layout()) = %d, want %d", got, 3)
	}

	var nilKS *KeySignature
	if got := nilKS.TotalSize(); got != 0 {
		t.Errorf("(*KeySignature)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := ks.PrettyString(0, true)
	if !strings.Contains(pretty, "Key Signature") {
		t.Errorf("KeySignature.PrettyString() = %q, want to contain %q", pretty, "Key Signature")
	}
}
