// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashStructureNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		alg Algorithm
	}{
		"sha256": {alg: AlgSHA256},
		"null":   {alg: AlgNull},
	}

	for name, tt := range tests {
		name := name
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := NewHashStructure(tt.alg)
			if h == nil {
				t.Fatal("NewHashStructure() = nil, want non-nil")
			}
			if h.HashAlg != tt.alg {
				t.Errorf("NewHashStructure(%v).HashAlg = %v, want %v", tt.alg, h.HashAlg, tt.alg)
			}
		})
	}
}

func TestHashStructureReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	want := &HashStructure{
		HashAlg:    AlgSHA256,
		HashBuffer: bytes.Repeat([]byte{0x7C}, 32),
	}

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("HashStructure.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("HashStructure.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got HashStructure
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("HashStructure.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("HashStructure.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.HashAlg != want.HashAlg {
		t.Errorf("HashStructure round-trip HashAlg = %v, want %v", got.HashAlg, want.HashAlg)
	}
	if !bytes.Equal(got.HashBuffer, want.HashBuffer) {
		t.Errorf("HashStructure round-trip HashBuffer = %v, want %v", got.HashBuffer, want.HashBuffer)
	}
}

func TestHashStructureMethods(t *testing.T) {
	t.Parallel()

	h := &HashStructure{
		HashAlg:    AlgSHA256,
		HashBuffer: bytes.Repeat([]byte{0x22}, 32),
	}

	size0, err := h.SizeOf(0)
	if err != nil {
		t.Fatalf("HashStructure.SizeOf(0) error = %v, want nil", err)
	}
	if size0 != 2 {
		t.Errorf("HashStructure.SizeOf(0) = %d, want %d", size0, 2)
	}

	size1, err := h.SizeOf(1)
	if err != nil {
		t.Fatalf("HashStructure.SizeOf(1) error = %v, want nil", err)
	}
	if size1 != 34 {
		t.Errorf("HashStructure.SizeOf(1) = %d, want %d", size1, 34)
	}

	offset1, err := h.OffsetOf(1)
	if err != nil {
		t.Fatalf("HashStructure.OffsetOf(1) error = %v, want nil", err)
	}
	if offset1 != 2 {
		t.Errorf("HashStructure.OffsetOf(1) = %d, want %d", offset1, 2)
	}

	if _, err := h.SizeOf(99); err == nil {
		t.Errorf("HashStructure.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := h.OffsetOf(99); err == nil {
		t.Errorf("HashStructure.OffsetOf(99) error = nil, want non-nil")
	}

	var nilHS *HashStructure
	if got := nilHS.TotalSize(); got != 0 {
		t.Errorf("(*HashStructure)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := h.PrettyString(0, true)
	if !strings.Contains(pretty, "Hash Structure") {
		t.Errorf("HashStructure.PrettyString() = %q, want to contain %q", pretty, "Hash Structure")
	}
}
