package manifest

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var pspDirectoryTableDataChunk = []byte{
	0x24, 0x50, 0x53, 0x50,
	0xcf, 0x55, 0x73, 0x1b,
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
	table, length, err := ParsePSPDirectoryTable(bytes.NewBuffer(append(pspDirectoryTableDataChunk, 0xff)))
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
		t.Errorf("BIOSCookie is incorrect: %d, expected: %d", table.PSPCookie, PSPDirectoryTableCookie)
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
