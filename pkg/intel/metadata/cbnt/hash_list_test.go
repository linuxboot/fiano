// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashListNew(t *testing.T) {
	t.Parallel()

	h := NewHashList()
	if h == nil {
		t.Fatal("NewHashList() = nil, want non-nil")
	}
	if h.Size != 4 {
		t.Errorf("NewHashList().Size = %d, want %d", h.Size, 4)
	}
	if err := h.Validate(); err != nil {
		t.Errorf("NewHashList().Validate() error = %v, want nil", err)
	}
}

func TestHashListValidateRejectsInvalidSize(t *testing.T) {
	t.Parallel()

	h := NewHashList()
	h.Size = 0

	if err := h.Validate(); err == nil {
		t.Errorf("HashList.Validate() error = nil, want non-nil")
	}
}

func TestHashListRehashRecursive(t *testing.T) {
	t.Parallel()

	h := &HashList{
		List: []HashStructure{{
			HashAlg:    AlgSHA256,
			HashBuffer: bytes.Repeat([]byte{0xA5}, 32),
		}},
	}
	h.RehashRecursive()

	wantSize := uint16(h.TotalSize())
	if h.Size != wantSize {
		t.Errorf("HashList.RehashRecursive() Size = %d, want %d", h.Size, wantSize)
	}
}

func TestHashListReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	want := &HashList{
		List: []HashStructure{{
			HashAlg:    AlgSHA256,
			HashBuffer: bytes.Repeat([]byte{0x5A}, 32),
		}},
	}
	want.Rehash()

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("HashList.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("HashList.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got HashList
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("HashList.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("HashList.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got.Size != want.Size {
		t.Errorf("HashList round-trip Size = %d, want %d", got.Size, want.Size)
	}
	if len(got.List) != len(want.List) {
		t.Fatalf("len(HashList round-trip List) = %d, want %d", len(got.List), len(want.List))
	}
	if got.List[0].HashAlg != want.List[0].HashAlg {
		t.Errorf("HashList round-trip List[0].HashAlg = %v, want %v", got.List[0].HashAlg, want.List[0].HashAlg)
	}
	if !bytes.Equal(got.List[0].HashBuffer, want.List[0].HashBuffer) {
		t.Errorf("HashList round-trip List[0].HashBuffer = %v, want %v", got.List[0].HashBuffer, want.List[0].HashBuffer)
	}
}

func TestHashListSizeOffsetAndTotal(t *testing.T) {
	t.Parallel()

	h := &HashList{
		List: []HashStructure{{
			HashAlg:    AlgSHA256,
			HashBuffer: bytes.Repeat([]byte{0xCC}, 32),
		}},
	}
	h.Rehash()

	size0, err := h.SizeOf(0)
	if err != nil {
		t.Fatalf("HashList.SizeOf(0) error = %v, want nil", err)
	}
	if size0 != 2 {
		t.Errorf("HashList.SizeOf(0) = %d, want %d", size0, 2)
	}

	offset1, err := h.OffsetOf(1)
	if err != nil {
		t.Fatalf("HashList.OffsetOf(1) error = %v, want nil", err)
	}
	if offset1 != 2 {
		t.Errorf("HashList.OffsetOf(1) = %d, want %d", offset1, 2)
	}

	if _, err := h.SizeOf(99); err == nil {
		t.Errorf("HashList.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := h.OffsetOf(99); err == nil {
		t.Errorf("HashList.OffsetOf(99) error = nil, want non-nil")
	}

	var nilList *HashList
	if got := nilList.TotalSize(); got != 0 {
		t.Errorf("(*HashList)(nil).TotalSize() = %d, want %d", got, 0)
	}
}

func TestHashListPrettyString(t *testing.T) {
	t.Parallel()

	h := NewHashList()
	got := h.PrettyString(0, true)
	if !strings.Contains(got, "Hash List") {
		t.Errorf("HashList.PrettyString() = %q, want to contain %q", got, "Hash List")
	}
}
