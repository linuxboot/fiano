// Copyright 2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestNewStructInfo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bgv      BootGuardVersion
		wantType string
		wantNil  bool
	}{
		"version_1_0": {bgv: Version10, wantType: "*cbnt.StructInfoBG"},
		"version_2_0": {bgv: Version20, wantType: "*cbnt.StructInfoCBNT"},
		"version_2_1": {bgv: Version21, wantType: "*cbnt.StructInfoCBNT"},
		"unknown":     {bgv: BootGuardVersion(0xFF), wantNil: true},
	}

	for name, tT := range tests {
		name := name
		tT := tT
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := NewStructInfo(tT.bgv)
			if tT.wantNil {
				if got != nil {
					t.Errorf("NewStructInfo(%v) = %T, want nil", tT.bgv, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("NewStructInfo(%v) = nil, want non-nil", tT.bgv)
			}

			if gotType := reflect.TypeOf(got).String(); gotType != tT.wantType {
				t.Errorf("NewStructInfo(%v) type = %s, want %s", tT.bgv, gotType, tT.wantType)
			}
		})
	}
}

func TestStructInfoBGMethods(t *testing.T) {
	t.Parallel()

	s := StructInfoBG{ID: StructureID{'S', 'T', 'R', 'U', 'C', 'T', 'B', 'G'}, Version: 0x10}

	if err := s.Validate(); err != nil {
		t.Errorf("StructInfoBG.Validate() error = %v, want nil", err)
	}

	if got := len(s.Layout()); got != 2 {
		t.Errorf("len(StructInfoBG.Layout()) = %d, want %d", got, 2)
	}

	if got := s.TotalSize(); got != 9 {
		t.Errorf("StructInfoBG.TotalSize() = %d, want %d", got, 9)
	}

	size0, err := s.SizeOf(0)
	if err != nil {
		t.Fatalf("StructInfoBG.SizeOf(0) error = %v, want nil", err)
	}
	if size0 != 8 {
		t.Errorf("StructInfoBG.SizeOf(0) = %d, want %d", size0, 8)
	}

	offset1, err := s.OffsetOf(1)
	if err != nil {
		t.Fatalf("StructInfoBG.OffsetOf(1) error = %v, want nil", err)
	}
	if offset1 != 8 {
		t.Errorf("StructInfoBG.OffsetOf(1) = %d, want %d", offset1, 8)
	}

	if _, err := s.SizeOf(99); err == nil {
		t.Errorf("StructInfoBG.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := s.OffsetOf(99); err == nil {
		t.Errorf("StructInfoBG.OffsetOf(99) error = nil, want non-nil")
	}

	var buf bytes.Buffer
	n, err := s.WriteTo(&buf)
	if err != nil {
		t.Fatalf("StructInfoBG.WriteTo() error = %v, want nil", err)
	}
	if n != int64(s.TotalSize()) {
		t.Errorf("StructInfoBG.WriteTo() bytes = %d, want %d", n, s.TotalSize())
	}

	var readTarget StructInfoBG
	n, err = readTarget.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("StructInfoBG.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(s.TotalSize()) {
		t.Errorf("StructInfoBG.ReadFrom() bytes = %d, want %d", n, s.TotalSize())
	}

	if got := s.StructInfo(); reflect.TypeOf(got).String() != "cbnt.StructInfoBG" {
		t.Errorf("StructInfoBG.StructInfo() type = %T, want cbnt.StructInfoBG", got)
	}

	pretty := s.PrettyString(0, true)
	if !strings.Contains(pretty, "Struct Info") {
		t.Errorf("StructInfoBG.PrettyString() = %q, want to contain %q", pretty, "Struct Info")
	}
}

func TestStructInfoCBNTMethods(t *testing.T) {
	t.Parallel()

	s := StructInfoCBNT{
		ID:          StructureID{'S', 'T', 'R', 'U', 'C', 'T', '2', '0'},
		Version:     0x20,
		Variable0:   0,
		ElementSize: 0x0020,
	}

	if err := s.Validate(); err != nil {
		t.Errorf("StructInfoCBNT.Validate() error = %v, want nil", err)
	}

	if got := len(s.Layout()); got != 4 {
		t.Errorf("len(StructInfoCBNT.Layout()) = %d, want %d", got, 4)
	}

	if got := s.TotalSize(); got != 12 {
		t.Errorf("StructInfoCBNT.TotalSize() = %d, want %d", got, 12)
	}

	size3, err := s.SizeOf(3)
	if err != nil {
		t.Fatalf("StructInfoCBNT.SizeOf(3) error = %v, want nil", err)
	}
	if size3 != 2 {
		t.Errorf("StructInfoCBNT.SizeOf(3) = %d, want %d", size3, 2)
	}

	offset3, err := s.OffsetOf(3)
	if err != nil {
		t.Fatalf("StructInfoCBNT.OffsetOf(3) error = %v, want nil", err)
	}
	if offset3 != 10 {
		t.Errorf("StructInfoCBNT.OffsetOf(3) = %d, want %d", offset3, 10)
	}

	if _, err := s.SizeOf(99); err == nil {
		t.Errorf("StructInfoCBNT.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := s.OffsetOf(99); err == nil {
		t.Errorf("StructInfoCBNT.OffsetOf(99) error = nil, want non-nil")
	}

	var buf bytes.Buffer
	n, err := s.WriteTo(&buf)
	if err != nil {
		t.Fatalf("StructInfoCBNT.WriteTo() error = %v, want nil", err)
	}
	if n != int64(s.TotalSize()) {
		t.Errorf("StructInfoCBNT.WriteTo() bytes = %d, want %d", n, s.TotalSize())
	}

	var readTarget StructInfoCBNT
	n, err = readTarget.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("StructInfoCBNT.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(s.TotalSize()) {
		t.Errorf("StructInfoCBNT.ReadFrom() bytes = %d, want %d", n, s.TotalSize())
	}

	if got := s.StructInfo(); reflect.TypeOf(got).String() != "cbnt.StructInfoCBNT" {
		t.Errorf("StructInfoCBNT.StructInfo() type = %T, want cbnt.StructInfoCBNT", got)
	}

	pretty := s.PrettyString(0, true)
	if !strings.Contains(pretty, "Struct Info") {
		t.Errorf("StructInfoCBNT.PrettyString() = %q, want to contain %q", pretty, "Struct Info")
	}
}

func TestStructureIDString(t *testing.T) {
	t.Parallel()

	id := StructureID{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}
	if got, want := id.String(), "ABCDEFGH"; got != want {
		t.Errorf("StructureID.String() = %q, want %q", got, want)
	}
}
