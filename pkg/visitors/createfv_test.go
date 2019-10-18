// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

type testLayout struct {
	Type   string
	offset uint64
	length uint64
}

func checkBRLayout(t *testing.T, br *uefi.BIOSRegion, layout []testLayout) {
	// basic check
	if len(br.Elements) != len(layout) {
		t.Fatalf("wrong number of elements in BIOSRegion, got %d want %d", len(br.Elements), len(layout))
	}

	var nextoffset uint64
	// check the final layout
	for i, e := range br.Elements {
		var offset, length uint64
		switch f := e.Value.(type) {
		case *uefi.FirmwareVolume:
			offset = f.FVOffset
			length = f.Length
		case *uefi.BIOSPadding:
			offset = f.Offset
			length = uint64(len(f.Buf()))
		default:
			t.Fatalf("Unexpected Element at %d: %s", i, e.Type)
		}
		if e.Type != layout[i].Type {
			t.Errorf("Wrong Element Type at %d, got %s, want %s", i, e.Type, layout[i].Type)
		}
		if offset != layout[i].offset {
			t.Errorf("Wrong Element offset at %d, got %#x, want %#x", i, offset, layout[i].offset)
		}
		if length != layout[i].length {
			t.Errorf("Wrong Element length at %d, got %#x, want %#x", i, length, layout[i].length)
		}
		// sanity check
		if layout[i].offset != nextoffset {
			t.Errorf("Next offset inconsistency got %#x, want %#x", layout[i].offset, nextoffset)
		}
		nextoffset = layout[i].offset + layout[i].length
	}
	if br.Length != nextoffset {
		t.Errorf("Next offset inconsistency got %#x, want %#x", br.Length, nextoffset)
	}

}

func TestInsertFVinBP(t *testing.T) {
	// Create an empty BIOSRegion
	buf := make([]byte, 0x10000)
	uefi.Erase(buf, uefi.Attributes.ErasePolarity)
	r, err := uefi.NewBIOSRegion(buf, nil, uefi.RegionTypeBIOS)
	if err != nil {
		t.Fatal(err)
	}
	br := r.(*uefi.BIOSRegion)

	// Create an FV in the middle to check
	// creation of padding before and after FV
	fv, err := createEmptyFirmwareVolume(0x8000, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	bp := br.Elements[0].Value.(*uefi.BIOSPadding)
	err = insertFVinBP(br, 0x8000, bp, 0, fv)
	if err != nil {
		t.Fatal(err)
	}
	// basic check
	if len(br.Elements) != 3 {
		t.Fatalf("wrong number of elements in BIOSRegion, got %d want 3", len(br.Elements))
	}

	// Create an FV at the beginning to check
	// - no padding creation before the FV
	// - no existing elements lost after the FV
	fv, err = createEmptyFirmwareVolume(0, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	bp = br.Elements[0].Value.(*uefi.BIOSPadding)
	err = insertFVinBP(br, 0, bp, 0, fv)
	if err != nil {
		t.Fatal(err)
	}
	// basic check
	if len(br.Elements) != 4 {
		t.Fatalf("wrong number of elements in BIOSRegion, got %d want 4", len(br.Elements))
	}

	// Create an FV just before first created FV to check
	// - no padding creation after the FV
	// - no existing elements lost before and after the FV
	fv, err = createEmptyFirmwareVolume(0x7000, 0x1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	bp = br.Elements[1].Value.(*uefi.BIOSPadding)
	err = insertFVinBP(br, 0x7000, bp, 1, fv)
	if err != nil {
		t.Fatal(err)
	}
	// basic check
	if len(br.Elements) != 5 {
		t.Fatalf("wrong number of elements in BIOSRegion, got %d want 4", len(br.Elements))
	}

	var want = []testLayout{
		{"*uefi.FirmwareVolume", 0, 0x1000},
		{"*uefi.BIOSPadding", 0x1000, 0x6000},
		{"*uefi.FirmwareVolume", 0x7000, 0x1000},
		{"*uefi.FirmwareVolume", 0x8000, 0x1000},
		{"*uefi.BIOSPadding", 0x9000, 0x7000},
	}
	checkBRLayout(t, br, want)
}

func TestCreateFV(t *testing.T) {
	// Set erasepolarity to FF
	uefi.Attributes.ErasePolarity = 0xFF
	// Create an empty BIOSRegion
	buf := make([]byte, 0x10000)
	uefi.Erase(buf, uefi.Attributes.ErasePolarity)
	r, err := uefi.NewBIOSRegion(buf, nil, uefi.RegionTypeBIOS)
	if err != nil {
		t.Fatal(err)
	}
	// Create the visitor
	v := &CreateFV{
		AbsOffset: 0x8000,
		Size:      0x1000,
		Name:      *guid.MustParse("DECAFBAD-0000-0000-0000-000000000000"),
	}

	if err := v.Run(r); err != nil {
		t.Fatalf("Failed to create firmware volume, got %v", err)
	}

	br := r.(*uefi.BIOSRegion)
	want := []testLayout{
		{"*uefi.BIOSPadding", 0x0000, 0x8000},
		{"*uefi.FirmwareVolume", 0x8000, 0x1000},
		{"*uefi.BIOSPadding", 0x9000, 0x7000},
	}
	checkBRLayout(t, br, want)

}
