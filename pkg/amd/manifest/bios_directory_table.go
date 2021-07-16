package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bytes2 "github.com/9elements/converged-security-suite/v2/pkg/bytes"
	"io"
	"strings"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

// BIOSDirectoryTableCookie is a special identifier of BIOS Directory table level 1
const BIOSDirectoryTableCookie = 0x44484224 // $BHD
// BIOSDirectoryTableLevel2Cookie is a special identifier of BIOS Directory table level 2
const BIOSDirectoryTableLevel2Cookie = 0x324C4224 // $BL2

// BIOSDirectoryTableEntryType is an entry type of BIOS Directory table
type BIOSDirectoryTableEntryType uint8

const (
	// APCBBinaryEntry denotes APCB binary entry in BIOS Directory table
	APCBBinaryEntry BIOSDirectoryTableEntryType = 0x60
	// BIOSRTMVolumeEntry denotes BIOS RTM Volume entry in BIOS Directory table
	BIOSRTMVolumeEntry BIOSDirectoryTableEntryType = 0x62
	// BIOSDirectoryTableLevel2Entry denotes an entry that points to BIOS Directory table level 2
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
	RomID      uint8

	Size               uint32
	SourceAddress      uint64
	DestinationAddress uint64
}

// BIOSDirectoryTableHeader represents a BIOS Directory Table Header
// Table 11 from (1)
type BIOSDirectoryTableHeader struct {
	BIOSCookie   uint32
	Checksum     uint32
	TotalEntries uint32
	Reserved     uint32
}

// BIOSDirectoryTable represents a BIOS Directory Table Header with all entries
// Table 11 & Table 12 from (1)
type BIOSDirectoryTable struct {
	BIOSDirectoryTableHeader

	Entries []BIOSDirectoryTableEntry
}

func (b BIOSDirectoryTable) String() string {
	var s strings.Builder
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, b.BIOSCookie)
	fmt.Fprintf(&s, "BIOS Cookie: 0x%x (%s)\n", b.BIOSCookie, cookieBytes)
	fmt.Fprintf(&s, "Checksum: %d\n", b.Checksum)
	fmt.Fprintf(&s, "Total Entries: %d\n", b.TotalEntries)
	fmt.Fprintf(&s, "%-5s | %-10s | %-10s | %-9s | %-8s | %-10s | %-8s | %-10s | %-5s | %-6s | %-13s | %-18s\n",
		"Type",
		"RegionType",
		"ResetImage",
		"CopyImage",
		"ReadOnly",
		"Compressed",
		"Instance",
		"Subprogram",
		"RomID",
		"Size",
		"SourceAddress",
		"DestinationAddress")
	fmt.Fprintf(&s, "%s\n", "----------------------------------------------------------------------------------------------------------------------------------------------------------------")
	for _, entry := range b.Entries {
		fmt.Fprintf(&s, "0x%-3x | 0x%-8x | %-10v | %-9v | %-8v | %-10v | 0x%-6x | 0x%-8x | 0x%-3x | %-6d | 0x%-11x | 0x%-18x\n",
			entry.Type,
			entry.RegionType,
			entry.ResetImage,
			entry.CopyImage,
			entry.ReadOnly,
			entry.Compressed,
			entry.Instance,
			entry.Subprogram,
			entry.RomID,
			entry.Size,
			entry.SourceAddress,
			entry.DestinationAddress)
	}
	return s.String()
}

// FindBIOSDirectoryTable scans firmware for BIOSDirectoryTableCookie
// and treats remaining bytes as BIOSDirectoryTable
func FindBIOSDirectoryTable(image []byte) (*BIOSDirectoryTable, bytes2.Range, error) {
	// there is no predefined address, search through the whole memory
	var cookieBytes [4]byte
	binary.LittleEndian.PutUint32(cookieBytes[:], BIOSDirectoryTableCookie)

	var offset uint64
	for {
		idx := bytes.Index(image, cookieBytes[:])
		if idx == -1 {
			break
		}

		table, bytesRead, err := ParseBIOSDirectoryTable(bytes.NewBuffer(image[idx:]))
		if err != nil {
			shift := uint64(idx + len(cookieBytes))
			image = image[shift:]
			offset += shift
			continue
		}
		return table, bytes2.Range{Offset: offset + uint64(idx), Length: bytesRead}, err
	}
	return nil, bytes2.Range{}, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

// ParseBIOSDirectoryTable converts input bytes into BIOSDirectoryTable
func ParseBIOSDirectoryTable(r io.Reader) (*BIOSDirectoryTable, uint64, error) {
	var table BIOSDirectoryTable
	var totalLength uint64
	if err := readAndCountSize(r, binary.LittleEndian, &table.BIOSCookie, &totalLength); err != nil {
		return nil, 0, err
	}
	if table.BIOSCookie != BIOSDirectoryTableCookie && table.BIOSCookie != BIOSDirectoryTableLevel2Cookie {
		return nil, 0, fmt.Errorf("incorrect cookie: %d", table.BIOSCookie)
	}

	if err := readAndCountSize(r, binary.LittleEndian, &table.Checksum, &totalLength); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &table.TotalEntries, &totalLength); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &table.Reserved, &totalLength); err != nil {
		return nil, 0, err
	}

	table.Entries = make([]BIOSDirectoryTableEntry, 0, table.TotalEntries)
	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, length, err := ParseBIOSDirectoryTableEntry(r)
		if err != nil {
			return nil, 0, err
		}
		table.Entries = append(table.Entries, *entry)
		totalLength += length
	}
	return &table, totalLength, nil
}

// ParseBIOSDirectoryTableEntry converts input bytes into BIOSDirectoryTableEntry
func ParseBIOSDirectoryTableEntry(r io.Reader) (*BIOSDirectoryTableEntry, uint64, error) {
	var entry BIOSDirectoryTableEntry
	var length uint64
	if err := readAndCountSize(r, binary.LittleEndian, &entry.Type, &length); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &entry.RegionType, &length); err != nil {
		return nil, 0, err
	}

	var flags uint8
	if err := readAndCountSize(r, binary.LittleEndian, &flags, &length); err != nil {
		return nil, 0, err
	}
	entry.ResetImage = (flags>>7)&0x1 != 0
	entry.CopyImage = (flags>>6)&0x1 != 0
	entry.ReadOnly = (flags>>5)&0x1 != 0
	entry.Compressed = (flags>>4)&0x1 != 0
	entry.Instance = flags >> 3

	if err := readAndCountSize(r, binary.LittleEndian, &flags, &length); err != nil {
		return nil, 0, err
	}
	entry.Subprogram = flags & 7
	entry.RomID = (flags >> 3) & 0x3

	if err := readAndCountSize(r, binary.LittleEndian, &entry.Size, &length); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &entry.SourceAddress, &length); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &entry.DestinationAddress, &length); err != nil {
		return nil, 0, err
	}
	return &entry, length, nil
}
