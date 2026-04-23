// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestChipsetACModuleInformationNew(t *testing.T) {
	t.Parallel()

	got := NewChipsetACModuleInformation()
	if got == nil {
		t.Fatal("NewChipsetACModuleInformation() = nil, want non-nil")
	}
	want := ChipsetACModuleInformation{}
	if *got != want {
		t.Errorf("NewChipsetACModuleInformation() = %+v, want zero-value struct", *got)
	}
}

func TestChipsetACModuleInformationReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	want := ChipsetACModuleInformation{
		UUID:            [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ChipsetACMType:  1,
		Version:         4,
		Length:          42,
		ChipsetIDList:   100,
		OsSinitDataVer:  101,
		MinMleHeaderVer: 102,
		Capabilities:    103,
		AcmVersion:      2,
		AcmRevision:     [3]uint8{3, 4, 5},
		ProcessorIDList: 104,
	}

	var buf bytes.Buffer
	n, err := want.WriteTo(&buf)
	if err != nil {
		t.Fatalf("ChipsetACModuleInformation.WriteTo() error = %v, want nil", err)
	}
	if n != int64(want.TotalSize()) {
		t.Errorf("ChipsetACModuleInformation.WriteTo() bytes = %d, want %d", n, want.TotalSize())
	}

	var got ChipsetACModuleInformation
	n, err = got.ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ChipsetACModuleInformation.ReadFrom() error = %v, want nil", err)
	}
	if n != int64(got.TotalSize()) {
		t.Errorf("ChipsetACModuleInformation.ReadFrom() bytes = %d, want %d", n, got.TotalSize())
	}

	if got != want {
		t.Errorf("ChipsetACModuleInformation round-trip = %+v, want %+v", got, want)
	}
}

func TestParseChipsetACModuleInformation(t *testing.T) {
	t.Parallel()

	t.Run("version_lt_5", func(t *testing.T) {
		acm := ChipsetACModuleInformation{Version: 4, Length: 0x1234}
		var buf bytes.Buffer
		if _, err := acm.WriteTo(&buf); err != nil {
			t.Fatalf("ChipsetACModuleInformation.WriteTo() error = %v, want nil", err)
		}

		got, err := ParseChipsetACModuleInformation(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("ParseChipsetACModuleInformation() error = %v, want nil", err)
		}
		if got.Version != 4 {
			t.Errorf("ParseChipsetACModuleInformation() Version = %d, want %d", got.Version, 4)
		}
	})

	t.Run("version_gte_5_reads_tpm_info_list", func(t *testing.T) {
		acm := ChipsetACModuleInformation{Version: 5}
		copy(acm.UUID[:], chipsetACModuleInformationSignature)
		wantTPMInfoList := uint32(0xAABBCCDD)

		var buf bytes.Buffer
		if _, err := acm.WriteTo(&buf); err != nil {
			t.Fatalf("ChipsetACModuleInformation.WriteTo() error = %v, want nil", err)
		}
		if err := binary.Write(&buf, binary.LittleEndian, wantTPMInfoList); err != nil {
			t.Fatalf("binary.Write(TPMInfoList) error = %v, want nil", err)
		}

		got, err := ParseChipsetACModuleInformation(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("ParseChipsetACModuleInformation() error = %v, want nil", err)
		}
		if got.TPMInfoList != wantTPMInfoList {
			t.Errorf("ParseChipsetACModuleInformation() TPMInfoList = 0x%x, want 0x%x", got.TPMInfoList, wantTPMInfoList)
		}
	})

	t.Run("version_gte_5_invalid_uuid", func(t *testing.T) {
		acm := ChipsetACModuleInformation{Version: 5}
		acm.UUID = [16]byte{0xFF}

		var buf bytes.Buffer
		if _, err := acm.WriteTo(&buf); err != nil {
			t.Fatalf("ChipsetACModuleInformation.WriteTo() error = %v, want nil", err)
		}
		if err := binary.Write(&buf, binary.LittleEndian, uint32(1)); err != nil {
			t.Fatalf("binary.Write(TPMInfoList) error = %v, want nil", err)
		}

		if _, err := ParseChipsetACModuleInformation(bytes.NewReader(buf.Bytes())); err == nil {
			t.Errorf("ParseChipsetACModuleInformation() error = nil, want non-nil")
		}
	})
}

func TestChipsetACModuleInformationMethods(t *testing.T) {
	t.Parallel()

	acm := NewChipsetACModuleInformation()

	if got := len(acm.Layout()); got != 12 {
		t.Errorf("len(ChipsetACModuleInformation.Layout()) = %d, want %d", got, 11)
	}

	size0, err := acm.SizeOf(0)
	if err != nil {
		t.Fatalf("ChipsetACModuleInformation.SizeOf(0) error = %v, want nil", err)
	}
	if size0 != 16 {
		t.Errorf("ChipsetACModuleInformation.SizeOf(0) = %d, want %d", size0, 16)
	}

	offset10, err := acm.OffsetOf(10)
	if err != nil {
		t.Fatalf("ChipsetACModuleInformation.OffsetOf(10) error = %v, want nil", err)
	}
	if offset10 != 40 {
		t.Errorf("ChipsetACModuleInformation.OffsetOf(10) = %d, want %d", offset10, 40)
	}

	if _, err := acm.SizeOf(99); err == nil {
		t.Errorf("ChipsetACModuleInformation.SizeOf(99) error = nil, want non-nil")
	}
	if _, err := acm.OffsetOf(99); err == nil {
		t.Errorf("ChipsetACModuleInformation.OffsetOf(99) error = nil, want non-nil")
	}

	var nilACM *ChipsetACModuleInformation
	if got := nilACM.TotalSize(); got != 0 {
		t.Errorf("(*ChipsetACModuleInformation)(nil).TotalSize() = %d, want %d", got, 0)
	}

	pretty := acm.PrettyString(0, true)
	if !strings.Contains(pretty, "Chipset AC Module Information") {
		t.Errorf("ChipsetACModuleInformation.PrettyString() = %q, want to contain %q", pretty, "Chipset AC Module Information")
	}
}
