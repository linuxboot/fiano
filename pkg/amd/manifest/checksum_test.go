// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"testing"
)

func TestFletcherCRC32(t *testing.T) {
	assertEqual := func(expected, actual uint32) {
		if expected != actual {
			t.Errorf("Expected: %d, but got: %d", expected, actual)
		}
	}
	assertEqual(0xF04FC729, fletcherCRC32([]byte("abcde")))
	assertEqual(0x56502D2A, fletcherCRC32([]byte("abcdef")))
	assertEqual(0xEBE19591, fletcherCRC32([]byte("abcdefgh")))
}

func TestPSPDirectoryCheckSum(t *testing.T) {
	actualCheckSum := CalculatePSPDirectoryCheckSum(pspDirectoryTableDataChunk)

	table, _, err := ParsePSPDirectoryTable(pspDirectoryTableDataChunk)
	if err != nil {
		t.Fatalf("Failed to parse PSP Directory table, err: %v", err)
	}
	if table.Checksum != actualCheckSum {
		t.Errorf("Incorrect checksum: 0x%X, expected: 0x%X", actualCheckSum, table.Checksum)
	}
}

func TestBIOSDirectoryCheckSum(t *testing.T) {
	actualCheckSum := CalculateBiosDirectoryCheckSum(biosDirectoryTableDataChunk)

	table, _, err := ParseBIOSDirectoryTable(biosDirectoryTableDataChunk)
	if err != nil {
		t.Fatalf("Failed to parse PSP Directory table, err: %v", err)
	}
	if table.Checksum != actualCheckSum {
		t.Errorf("Incorrect checksum: 0x%X, expected: 0x%X", actualCheckSum, table.Checksum)
	}
}
