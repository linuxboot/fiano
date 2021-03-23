package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

const BIOSDirectoryTableCookie = 0x24424844       // $BHD
const BIOSDirectoryTableLevel2Cookie = 0x24424c32 // $BL2

type BIOSDirectoryTableEntryType uint8

const (
	APCBBinaryEntry               BIOSDirectoryTableEntryType = 0x60
	BIOSDirectoryTableLevel2Entry BIOSDirectoryTableEntryType = 0x70
)

// BIOSDirectoryTableEntry represents a single entry in BIOS Directory Table
// Table 12 from (1)
type BIOSDirectoryTableEntry struct {
	Type       BIOSDirectoryTableEntryType
	RegionType uint8

	ResetImage bool
	CopyImage  bool
	ReadOnly   bool
	Compressed bool
	Instance   uint8
	Subprogram uint8
	RomId      uint8

	Size               uint32
	SourceAddress      uint64
	DestinationAddress uint64
}

// BIOSDirectoryTable represents a BIOS Directory Table Header with all entries
// Table 11 from (1)
type BIOSDirectoryTable struct {
	BIOSCookie   uint32
	Checksum     uint32
	TotalEntries uint32
	Reserved     uint32

	Entries []BIOSDirectoryTableEntry
}

// FindBIOSDirectoryTable scans firmware for BIOSDirectoryTableCookie
// and treats remaining bytes as BIOSDirectoryTable
func FindBIOSDirectoryTable(firmware Firmware) (*BIOSDirectoryTable, uint64, error) {
	// there is no predefined address, search through the whole memory
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, BIOSDirectoryTableCookie)

	image := firmware.ImageBytes()

	var offset uint64
	for {
		idx := bytes.Index(image, cookieBytes)
		if idx == -1 {
			break
		}

		table, err := ParseBIOSDirectoryTable(bytes.NewBuffer(image[idx:]))
		offset += uint64(idx)
		if err != nil {
			image = image[idx+len(cookieBytes):]
			continue
		}

		return table, firmware.OffsetToPhysAddr(offset), err
	}

	return nil, 0, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

// ParseBIOSDirectoryTable converts input bytes into BIOSDirectoryTable
func ParseBIOSDirectoryTable(r io.Reader) (*BIOSDirectoryTable, error) {
	var table BIOSDirectoryTable
	if err := binary.Read(r, binary.BigEndian, &table.BIOSCookie); err != nil {
		return nil, err
	}
	if table.BIOSCookie != BIOSDirectoryTableCookie && table.BIOSCookie != BIOSDirectoryTableLevel2Cookie {
		return nil, fmt.Errorf("incorrect cookie: %d", table.BIOSCookie)
	}

	if err := binary.Read(r, binary.LittleEndian, &table.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.TotalEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.Reserved); err != nil {
		return nil, err
	}

	table.Entries = make([]BIOSDirectoryTableEntry, 0, table.TotalEntries)
	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, err := ParseBIOSDirectoryTableEntry(r)
		if err != nil {
			return nil, err
		}
		table.Entries = append(table.Entries, *entry)
	}
	return &table, nil
}

// ParseBIOSDirectoryTableEntry converts input bytes into BIOSDirectoryTableEntry
func ParseBIOSDirectoryTableEntry(r io.Reader) (*BIOSDirectoryTableEntry, error) {
	var entry BIOSDirectoryTableEntry
	if err := binary.Read(r, binary.LittleEndian, &entry.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.RegionType); err != nil {
		return nil, err
	}

	var flags uint8
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	entry.ResetImage = (flags>>7)&0x1 != 0
	entry.CopyImage = (flags>>6)&0x1 != 0
	entry.ReadOnly = (flags>>5)&0x1 != 0
	entry.Compressed = (flags>>4)&0x1 != 0
	entry.Instance = flags >> 3

	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	entry.Subprogram = flags & 7
	entry.RomId = (flags >> 3) & 0x3

	if err := binary.Read(r, binary.LittleEndian, &entry.Size); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.SourceAddress); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.DestinationAddress); err != nil {
		return nil, err
	}
	return &entry, nil
}
