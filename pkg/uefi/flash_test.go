// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

var (
	// Signature examples
	emptySig      = make([]byte, 40)                            // Empty flash signature
	ichSig        = append(FlashSignature, make([]byte, 20)...) // Old ICH version
	pchSig        = append(make([]byte, 16), FlashSignature...) // New PCH version
	misalignedSig = append(append(make([]byte, 10), FlashSignature...),
		make([]byte, 20)...) // Misaligned flash signature

	// FlashRegion Examples
	fr1 = FlashRegion{Base: 1, Limit: 1}
	fr2 = FlashRegion{Base: 2, Limit: 2}
	fr3 = FlashRegion{Base: 3, Limit: 3}
	// Region Examples
	rr1 = &RawRegion{FRegion: &fr1, RegionType: RegionTypeUnknown}
	br  = &BIOSRegion{FRegion: &fr2, RegionType: RegionTypeBIOS}
	rr2 = &RawRegion{FRegion: &fr3, RegionType: RegionTypeUnknown}
	// Empty buffer
	emptyFlashBuf = make([]byte, 0x4000)

	// FlashImage Region test examples
	trr1 = MakeTyped(rr1)
	trr2 = MakeTyped(rr2)
	tbr  = MakeTyped(br)
	f1   = FlashImage{buf: emptyFlashBuf, FlashSize: 0x4000, Regions: []*TypedFirmware{trr1, tbr, trr2}} // Full image
	f2   = FlashImage{buf: emptyFlashBuf, FlashSize: 0x4000, Regions: []*TypedFirmware{tbr, trr2}}       // Front gap
	f3   = FlashImage{buf: emptyFlashBuf, FlashSize: 0x4000, Regions: []*TypedFirmware{trr1, tbr}}       // Back gap
	f4   = FlashImage{buf: emptyFlashBuf, FlashSize: 0x4000, Regions: []*TypedFirmware{trr1, trr1}}      // Overlap!
	// Final result
	regions = []*TypedFirmware{trr1, tbr, trr2}
)

func TestFindSignature(t *testing.T) {
	var tests = []struct {
		name   string
		buf    []byte
		offset int
		err    error
	}{
		{"empty buffer", nil, -1, ErrTooShort},
		{"short buffer", []byte{1, 2, 3}, -1, ErrTooShort},
		{"empty signature", emptySig, -1, os.ErrNotExist},
		{"ichSign", ichSig, 4, nil},
		{"pchSig", pchSig, 20, nil},
		{"misaligned sig", misalignedSig, -1, os.ErrNotExist},
	}
	for _, test := range tests {
		f := FlashImage{buf: test.buf}
		offset, err := f.FindSignature()
		if offset != test.offset {
			t.Errorf("Offset was not correct, expected %v, got %v", test.offset, offset)
		}
		if !errors.Is(err, test.err) {
			t.Errorf("%s: got %v, want %v", test.name, err, test.err)
		}
	}
}

func TestIsPCH(t *testing.T) {
	var tests = []struct {
		buf []byte
		out bool
	}{
		{emptySig, false},
		{ichSig, false},
		{pchSig, true},
		{misalignedSig, false},
	}
	for _, test := range tests {
		f := FlashImage{buf: test.buf}
		out := f.IsPCH()
		if out != test.out {
			t.Errorf("IsPCH was not correct, expected %v, got %v for \n%s", test.out, out, hex.Dump(test.buf))
		}
	}
}

func TestFillRegionGaps(t *testing.T) {
	var tests = []struct {
		name string
		f    FlashImage
		out  []*TypedFirmware // expected output after gap filling
		msg  string           // Error message
	}{
		{"FullImage", f1, regions, ""},
		{"FrontRegionGap", f2, regions, ""},
		{"BackRegionGap", f3, regions, ""},
		{"OverlapRegion", f4, nil, "overlapping regions! region type Unknown Region (-1) overlaps with the previous region"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.f.fillRegionGaps()

			// Check error regions
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
			// for cases with no error
			if test.msg == "" {
				if len(test.out) != len(test.f.Regions) {
					t.Fatalf("Mismatched Region length! Expected %d regions, got %d", len(test.out), len(test.f.Regions))
				}
				for i := range test.out {
					ans := test.out[i].Value.(Region)
					reg := test.f.Regions[i].Value.(Region)
					if ans.Type() != reg.Type() {
						t.Errorf("Region type mismatch, expected \n%v\n got \n%v\n", ans.Type(), reg.Type())
					}
					afr := ans.FlashRegion()
					rfr := reg.FlashRegion()
					if afr.Base != rfr.Base {
						t.Errorf("Region base mismatch, expected \n%v\n got \n%v\n", afr.Base, rfr.Base)
					}
					if afr.Limit != rfr.Limit {
						t.Errorf("Region Limit mismatch, expected \n%v\n got \n%v\n", afr.Limit, rfr.Limit)
					}
				}
			}
		})
	}
}
