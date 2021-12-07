// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"encoding/binary"
	"testing"
)

var pspDirectoryTableDataChunk = []byte{
	0x24, 0x50, 0x53, 0x50,
	0x57, 0x4d, 0x3f, 0xfc,
	0x01, 0x00, 0x00, 0x00,
	0x10, 0x05, 0x00, 0x20,

	0x00,
	0x00,
	0x00, 0x00,
	0x40, 0x04, 0x00, 0x00,
	0x00, 0x24, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestPSPDirectoryTableHeaderSize(t *testing.T) {
	const expectedPSPDirectoryTableHeaderSize = 0x10
	actualSize := binary.Size(PSPDirectoryTableHeader{})
	if actualSize != expectedPSPDirectoryTableHeaderSize {
		t.Errorf("BIOSDirectoryTableHeader is incorrect: %d, expected %d", actualSize, expectedPSPDirectoryTableHeaderSize)
	}
}

func TestFindPSPDirectoryTable(t *testing.T) {
	firmwareChunk := []byte{
		0x12, 0x00, 0x15, 0x00, 0x15, // some prefix
	}

	t.Run("no_psp_table_cookie", func(t *testing.T) {
		table, _, err := FindPSPDirectoryTable(firmwareChunk)
		if err == nil {
			t.Errorf("Expected an error when finding psp directory table in a broken firmware")
		}
		if table != nil {
			t.Errorf("Returned PSP Directory table is not nil")
		}
	})

	t.Run("psp_table_cookie_found", func(t *testing.T) {
		table, r, err := FindPSPDirectoryTable(append(firmwareChunk, pspDirectoryTableDataChunk...))
		if err != nil {
			t.Fatalf("Unexecpted error when finding PSP Directory table")
		}
		if r.Offset != uint64(len(firmwareChunk)) {
			t.Fatalf("PSP Directory Table address is incorrect: %d, expected: %d", r.Offset, uint64(len(firmwareChunk)))
		}
		if r.Length != uint64(len(pspDirectoryTableDataChunk)) {
			t.Errorf("PSP Directory Table size is incorrect: %d, expected: %d", r.Length, uint64(len(pspDirectoryTableDataChunk)))
		}
		if table == nil {
			t.Fatal("Returned PSP Directory table is nil")
		}
	})
}

func TestPspDirectoryTableParsing(t *testing.T) {
	data := append(pspDirectoryTableDataChunk, 0xff)
	table, length, err := ParsePSPDirectoryTable(data)
	if err != nil {
		t.Fatalf("Failed to parse PSP Directory table, err: %v", err)
	}
	if length != uint64(len(pspDirectoryTableDataChunk)) {
		t.Errorf("PSP Directory table read bytes is incorrect: %d, expected: %d", length, len(biosDirectoryTableDataChunk))
	}
	if table == nil {
		t.Fatal("result PSP Directory table is nil")
	}

	if table.PSPCookie != PSPDirectoryTableCookie {
		t.Errorf("PSPCookie is incorrect: %d, expected: %d", table.PSPCookie, PSPDirectoryTableCookie)
	}
	if table.Checksum != 0xfc3f4d57 {
		t.Errorf("Checksum is incorrect: %d, expected: %d", table.Checksum, 0xfc3f4d57)
	}
	if table.TotalEntries != 1 {
		t.Errorf("TotalEntries is incorrect: %d, expected: %d", table.TotalEntries, 1)
	}
	if len(table.Entries) != 1 {
		t.Fatalf("Result number of entries is incorrect: %d, expected: %d", len(table.Entries), 1)
	}

	if table.Entries[0].Type != AMDPublicKeyEntry {
		t.Errorf("Table entry [0] type is incorrect: %d, expected: %d", table.Entries[0].Type, AMDPublicKeyEntry)
	}
	if table.Entries[0].Subprogram != 0 {
		t.Errorf("Table entry [0] subprogram is incorrect: %d, expected: %d", table.Entries[0].Subprogram, 0)
	}
	if table.Entries[0].LocationOrValue != 0x62400 {
		t.Errorf("Table entry [0] location is incorrect: %d, expected: 0x62400", table.Entries[0].LocationOrValue)
	}
}

func TestBrokenTotalEntriesPspDirectoryParsing(t *testing.T) {
	pspDirectoryTableData := make([]byte, len(pspDirectoryTableDataChunk))
	copy(pspDirectoryTableData, pspDirectoryTableDataChunk)

	// 8 is offset of TotalEntries field
	pspDirectoryTableData[8] = 0xff
	pspDirectoryTableData[9] = 0xff
	pspDirectoryTableData[10] = 0xff
	pspDirectoryTableData[11] = 0xff

	_, _, err := ParsePSPDirectoryTable(pspDirectoryTableData)
	if err == nil {
		t.Errorf("expected error when parsing incorrect psp directory table contents")
	}
}
