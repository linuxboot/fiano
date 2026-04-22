// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashStructureFillNew(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		alg Algorithm
	}{
		"sha384": {alg: AlgSHA384},
		"null":   {alg: AlgNull},
	}

	for name, tt := range tests {
		name := name
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := NewHashStructureFill(tt.alg)
			if h == nil {
				t.Fatal("NewHashStructureFill() = nil, want non-nil")
			}
			if h.HashAlg != tt.alg {
				t.Errorf("NewHashStructureFill(%v).HashAlg = %v, want %v", tt.alg, h.HashAlg, tt.alg)
			}
		})
	}
}

func TestHashStructureFillHashBufferSizeByAlgorithm(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		alg      Algorithm
		wantSize uint64
	}{
		"sha256": {alg: AlgSHA256, wantSize: 34},
		"null":   {alg: AlgNull, wantSize: 34},
		"unknown": {
			alg:      AlgRSA,
			wantSize: 2,
		},
	}

	for name, tt := range tests {
		name := name
		tt := tt

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := &HashStructureFill{HashAlg: tt.alg}
			size, err := h.SizeOf(1)
			if err != nil {
				t.Fatalf("HashStructureFill.SizeOf(1) error = %v, want nil", err)
			}
			if size != tt.wantSize {
				t.Errorf("HashStructureFill.SizeOf(1) with alg %v = %d, want %d", tt.alg, size, tt.wantSize)
			}
		})
	}
}

func TestHashStructureFillReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	want := &HashStructureFill{
		HashAlg:    AlgSHA256,
		HashBuffer: bytes.Repeat([]byte{0x33}, 34),
	}

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("HashStructureFill.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("HashStructureFill.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got HashStructureFill
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("HashStructureFill.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("HashStructureFill.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.HashAlg != want.HashAlg {
		t.Errorf("HashStructureFill round-trip HashAlg = %v, want %v", got.HashAlg, want.HashAlg)
	}
	if !bytes.Equal(got.HashBuffer, want.HashBuffer) {
		t.Errorf("HashStructureFill round-trip HashBuffer = %v, want %v", got.HashBuffer, want.HashBuffer)
	}
}

func TestHashStructureFillMethods(t *testing.T) {
	t.Parallel()

	h := &HashStructureFill{HashAlg: AlgSHA256, HashBuffer: bytes.Repeat([]byte{0x10}, 34)}

	offset1, err := h.OffsetOf(1)
	if err != nil {
		t.Fatalf("HashStructureFill.OffsetOf(1) error = %v, want nil", err)
	}
	if offset1 != 2 {
		t.Errorf("HashStructureFill.OffsetOf(1) = %d, want %d", offset1, 2)
	}

	if _, err := h.SizeOf(99); err == nil {
		t.Errorf("HashStructureFill.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := h.OffsetOf(99); err == nil {
		t.Errorf("HashStructureFill.OffsetOf(99) error = nil, want non-nil")
	}

	var nilHS *HashStructureFill
	if got := nilHS.TotalSize(); got != 0 {
		t.Errorf("(*HashStructureFill)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := h.PrettyString(0, true)
	if !strings.Contains(pretty, "Hash Structure Fill") {
		t.Errorf("HashStructureFill.PrettyString() = %q, want to contain %q", pretty, "Hash Structure Fill")
	}
}
