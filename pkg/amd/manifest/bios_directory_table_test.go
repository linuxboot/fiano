// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"encoding/binary"
	"testing"
)

var biosDirectoryTableDataChunk = []byte{
	0x24, 0x42, 0x48, 0x44,
	0xd0, 0x75, 0xc5, 0xac,
	0x01, 0x00, 0x00, 0x00,
	0x40, 0x04, 0x00, 0x20,

	0x68,
	0x00,
	0x10,
	0x01,
	0x00, 0x20, 0x00, 0x00,
	0x00, 0x30, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

func TestBIOSDirectoryTableHeaderSize(t *testing.T) {
	const expectedBIOSDirectoryTableHeaderSize = 0x10
	actualSize := binary.Size(BIOSDirectoryTableHeader{})
	if actualSize != expectedBIOSDirectoryTableHeaderSize {
		t.Errorf("BIOSDirectoryTableHeader is incorrect: %d, expected %d", actualSize, expectedBIOSDirectoryTableHeaderSize)
	}
}

func TestFindBIOSDirectoryTable(t *testing.T) {
	firmwareChunk := []byte{
		0x12, 0x00, 0x15, 0x00, 0x15, // some prefix
	}

	t.Run("no_bios_table_cookie", func(t *testing.T) {
		table, _, err := FindBIOSDirectoryTable(firmwareChunk)
		if err == nil {
			t.Errorf("Expected an error when finding bios directory table in a broken firmware")
		}
		if table != nil {
			t.Errorf("Returned BIOS Directory table is not nil")
		}
	})

	t.Run("bios_table_cookie_found", func(t *testing.T) {
		table, r, err := FindBIOSDirectoryTable(append(firmwareChunk, biosDirectoryTableDataChunk...))
		if err != nil {
			t.Fatalf("Unexecpted error when finding BIOS Directory table: %v", err)
		}
		if r.Offset != uint64(len(firmwareChunk)) {
			t.Errorf("BIOS Directory Table address is incorrect: %d, expected: %d", r.Offset, uint64(len(firmwareChunk)))
		}
		if r.Length != uint64(len(biosDirectoryTableDataChunk)) {
			t.Errorf("BIOS Directory Table size is incorrect: %d, expected: %d", r.Length, uint64(len(biosDirectoryTableDataChunk)))
		}
		if table == nil {
			t.Errorf("Returned BIOS Directory table is nil")
		}
	})
}

func TestBiosDirectoryTableParsing(t *testing.T) {
	table, readBytes, err := ParseBIOSDirectoryTable(append(biosDirectoryTableDataChunk, 0xff))
	if err != nil {
		t.Fatalf("Failed to parse BIOS Directory table, err: %v", err)
	}
	if readBytes != uint64(len(biosDirectoryTableDataChunk)) {
		t.Errorf("BIOS Directory table read bytes is incorrect: %d, expected: %d", readBytes, len(biosDirectoryTableDataChunk))
	}
	if table == nil {
		t.Fatalf("result BIOS Directory table is nil")
	}

	if table.BIOSCookie != BIOSDirectoryTableCookie {
		t.Errorf("BIOSCookie is incorrect: %d, expected: %d", table.BIOSCookie, BIOSDirectoryTableCookie)
	}
	if table.Checksum != 0xacc575d0 {
		t.Errorf("Checksum is incorrect: %d, expected: %d", table.Checksum, 0xacc575d0)
	}
	if table.TotalEntries != 1 {
		t.Errorf("TotalEntries is incorrect: %d, expected: %d", table.TotalEntries, 1)
	}
	if len(table.Entries) != 1 {
		t.Fatalf("Result number of entries is incorrect: %d, expected: %d", len(table.Entries), 1)
	}

	entry := table.Entries[0]
	if entry.Type != 0x68 {
		t.Errorf("Table entry [0] type is incorrect: %d, expected: %d", table.Entries[0].Type, 0x68)
	}
	if entry.ResetImage {
		t.Errorf("Table entry [0] reset image is incorrect, expected false")
	}
	if entry.CopyImage {
		t.Errorf("Table entry [0] copy image is incorrect, expected false")
	}
	if entry.ReadOnly {
		t.Errorf("Table entry [0] read only is incorrect, expected false")
	}
	if entry.Compressed {
		t.Errorf("Table entry [0] compress is incorrect, expected false")
	}
	if entry.Instance != 1 {
		t.Errorf("Table entry [0] instance is incorrect, expected 1, got: %d", entry.Instance)
	}
	if entry.Subprogram != 1 {
		t.Errorf("Table entry [0] subprogram is incorrect, expected 1, got: %d", entry.Subprogram)
	}
	if entry.RomID != 0 {
		t.Errorf("Table entry [0] subprogram is incorrect, expected 9, got: %d", entry.RomID)
	}
	if entry.SourceAddress != 0x173000 {
		t.Errorf("Table entry [0] source address is incorrect: %x, expected: 0x173000",
			table.Entries[0].SourceAddress)
	}
	if entry.DestinationAddress != 0xffffffffffffffff {
		t.Errorf("Table entry [0] destination address is incorrect: %x, expected: 0xffffffffffffffff",
			table.Entries[0].DestinationAddress)
	}
}

func TestBrokenTotalEntriesBiosDirectoryParsing(t *testing.T) {
	biosDirectoryTableData := make([]byte, len(biosDirectoryTableDataChunk))
	copy(biosDirectoryTableData, biosDirectoryTableDataChunk)

	// 8 is offset of TotalEntries field
	biosDirectoryTableData[8] = 0xff
	biosDirectoryTableData[9] = 0xff
	biosDirectoryTableData[10] = 0xff
	biosDirectoryTableData[11] = 0xff

	_, _, err := ParseBIOSDirectoryTable(biosDirectoryTableData)
	if err == nil {
		t.Errorf("expected error when parsing incorrect psp directory table contents")
	}
}
