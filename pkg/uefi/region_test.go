// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import "testing"

var regionTestcases = [...]struct {
	in    FlashRegion
	valid bool
	base  uint32
	end   uint32
}{
	// Invalid
	{
		in:    FlashRegion{0, 0},
		valid: false,
		base:  0,
		end:   0x1000,
	},
	{
		in:    FlashRegion{1, 0},
		valid: false,
		base:  0x1000,
		end:   0x1000,
	},
	// Valid
	{
		in:    FlashRegion{1, 1},
		valid: true,
		base:  0x1000,
		end:   0x2000,
	},
	{
		in:    FlashRegion{100, 200},
		valid: true,
		base:  0x64000,
		end:   0xC9000,
	},
	{
		in:    FlashRegion{0x0004, 0xFFFF},
		valid: false,
		base:  0x00004000,
		end:   0x10000000,
	},
	{
		in:    FlashRegion{0x0004, 0xFFFE},
		valid: true,
		base:  0x00004000,
		end:   0x0FFFF000,
	},
	{
		in:    FlashRegion{0xFFFF, 0xFFFF},
		valid: false,
		base:  0x0FFFF000,
		end:   0x10000000,
	},
}

func TestFlashRegionValid(t *testing.T) {
	for _, tc := range regionTestcases {
		if out := tc.in.Valid(); out != tc.valid {
			t.Errorf("%#v.Valid() = %v; want = %v", tc.in, out, tc.valid)
		}
	}
}

func TestFlashRegionBaseOffset(t *testing.T) {
	for _, tc := range regionTestcases {
		if out := tc.in.BaseOffset(); out != tc.base {
			t.Errorf("%#v.BaseOffset() = %d; want = %d", tc.in, out, tc.base)
		}
	}
}

func TestFlashRegionEndOffset(t *testing.T) {
	for _, tc := range regionTestcases {
		if out := tc.in.EndOffset(); out != tc.end {
			t.Errorf("%#v.EndOffset() = %d; want = %d", tc.in, out, tc.end)
		}
	}
}
