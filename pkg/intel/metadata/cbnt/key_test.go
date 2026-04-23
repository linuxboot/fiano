// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestKeyNewAndValidate(t *testing.T) {
	t.Parallel()

	k := NewKey()
	if k == nil {
		t.Fatal("NewKey() = nil, want non-nil")
	}
	if k.Version != 0x10 {
		t.Errorf("NewKey().Version = 0x%x, want 0x10", k.Version)
	}
	if err := k.Validate(); err != nil {
		t.Errorf("NewKey().Validate() error = %v, want nil", err)
	}
}

func TestKeySetPubKeyAndPubKeyRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
	}

	k := NewKey()
	if err := k.SetPubKey(&key.PublicKey); err != nil {
		t.Fatalf("Key.SetPubKey(RSA) error = %v, want nil", err)
	}

	gotPub, err := k.PubKey()
	if err != nil {
		t.Fatalf("Key.PubKey() error = %v, want nil", err)
	}
	rsaPub, ok := gotPub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Key.PubKey() type = %T, want %T", gotPub, &rsa.PublicKey{})
	}

	if rsaPub.E != key.E {
		t.Errorf("Key.PubKey().E = %d, want %d", rsaPub.E, key.E)
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Errorf("Key.PubKey().N = %x, want %x", rsaPub.N.Bytes(), key.N.Bytes())
	}
}

func TestKeySetPubKeyAndPubKeyECDSA(t *testing.T) {
	key := ecdsaP256with32b(t)

	k := NewKey()
	if err := k.SetPubKey(&key.PublicKey); err != nil {
		t.Fatalf("Key.SetPubKey(ECDSA) error = %v, want nil", err)
	}

	gotPub, err := k.PubKey()
	if err != nil {
		t.Fatalf("Key.PubKey() error = %v, want nil", err)
	}
	ecdsaPub, ok := gotPub.(ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Key.PubKey() type = %T, want %T", gotPub, ecdsa.PublicKey{})
	}

	if ecdsaPub.X.Cmp(key.X) != 0 {
		t.Errorf("Key.PubKey().X = %x, want %x", ecdsaPub.X.Bytes(), key.X.Bytes())
	}
	if ecdsaPub.Y.Cmp(key.Y) != 0 {
		t.Errorf("Key.PubKey().Y = %x, want %x", ecdsaPub.Y.Bytes(), key.Y.Bytes())
	}
}

func TestKeyPubKeyErrors(t *testing.T) {
	t.Parallel()

	k := Key{KeyAlg: AlgRSA}
	k.KeySize.SetInBytes(256)
	k.Data = []byte{1}
	if _, err := k.PubKey(); err == nil {
		t.Errorf("Key.PubKey() with invalid data length error = nil, want non-nil")
	}

	k = Key{KeyAlg: AlgSHA1}
	if _, err := k.PubKey(); err == nil {
		t.Errorf("Key.PubKey() with unexpected algorithm error = nil, want non-nil")
	}
}

func TestKeySetPubKeyUnexpectedType(t *testing.T) {
	t.Parallel()

	k := NewKey()
	if err := k.SetPubKey(struct{}{}); err == nil {
		t.Errorf("Key.SetPubKey(struct{}{}) error = nil, want non-nil")
	}
}

func TestKeyReadWriteRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
	}

	want := NewKey()
	if err := want.SetPubKey(&key.PublicKey); err != nil {
		t.Fatalf("Key.SetPubKey() error = %v, want nil", err)
	}

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("Key.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("Key.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got Key
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("Key.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("Key.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.KeyAlg != want.KeyAlg {
		t.Errorf("Key round-trip KeyAlg = %v, want %v", got.KeyAlg, want.KeyAlg)
	}
	if got.KeySize != want.KeySize {
		t.Errorf("Key round-trip KeySize = %v, want %v", got.KeySize, want.KeySize)
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Errorf("Key round-trip Data = %v, want %v", got.Data, want.Data)
	}
}

func TestKeyMethods(t *testing.T) {
	t.Parallel()

	k := NewKey()

	if got := len(k.Layout()); got != 4 {
		t.Errorf("len(Key.Layout()) = %d, want %d", got, 4)
	}

	if _, err := k.SizeOf(99); err == nil {
		t.Errorf("Key.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := k.OffsetOf(99); err == nil {
		t.Errorf("Key.OffsetOf(99) error = nil, want non-nil")
	}

	var nilKey *Key
	if got := nilKey.TotalSize(); got != 0 {
		t.Errorf("(*Key)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := k.PrettyString(0, true)
	if !strings.Contains(pretty, "Key") {
		t.Errorf("Key.PrettyString() = %q, want to contain %q", pretty, "Key")
	}
}

func TestKeyPrintMethodsErrorPaths(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v, want nil", err)
	}

	k := NewKey()
	if err := k.SetPubKey(&key.PublicKey); err != nil {
		t.Fatalf("Key.SetPubKey() error = %v, want nil", err)
	}

	if err := k.PrintKMPubKey(AlgSHA1); err == nil {
		t.Errorf("Key.PrintKMPubKey(AlgSHA1) error = nil, want non-nil")
	}

	if err := k.PrintBPMPubKey(AlgRSA); err == nil {
		t.Errorf("Key.PrintBPMPubKey(AlgRSA) error = nil, want non-nil")
	}
}

func TestBitSizeMethods(t *testing.T) {
	t.Parallel()

	var bs BitSize
	bs.SetInBytes(8)
	if got := bs.InBits(); got != 64 {
		t.Errorf("BitSize.InBits() after SetInBytes(8) = %d, want %d", got, 64)
	}
	bs.SetInBits(24)
	if got := bs.InBytes(); got != 3 {
		t.Errorf("BitSize.InBytes() after SetInBits(24) = %d, want %d", got, 3)
	}

	var buf bytes.Buffer
	n, err := bs.WriteTo(&buf)
	if err != nil {
		t.Fatalf("BitSize.WriteTo() error = %v, want nil", err)
	}
	if n != int64(bs.TotalSize()) {
		t.Errorf("BitSize.WriteTo() bytes = %d, want %d", n, bs.TotalSize())
	}

	var got BitSize
	n, err = (&got).ReadFrom(&buf)
	if err == nil {
		t.Fatalf("BitSize.ReadFrom() error = nil, want non-nil")
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("BitSize.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}
}

func ecdsaP256with32b(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	for {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v, want nil", err)
		}
		if len(k.X.Bytes()) == 32 && len(k.Y.Bytes()) == 32 {
			return k
		}
	}
}
