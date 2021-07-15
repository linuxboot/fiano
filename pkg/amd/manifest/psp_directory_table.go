package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

// PSPDirectoryTableCookie is a special identifier of PSP Directory table level 1
const PSPDirectoryTableCookie = 0x50535024 // "$PSP"
// PSPDirectoryTableLevel2Cookie is a special identifier of PSP Directory table level 2
const PSPDirectoryTableLevel2Cookie = 0x324C5024 // "$PL2"

// PSPDirectoryTableEntryType is an entry type of PSP Directory table
type PSPDirectoryTableEntryType uint8

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry PSPDirectoryTableEntryType = 0x00
	// PSPBootloaderFirmwareEntry denotes a PSP bootloader firmware entry in PSP Directory table
	PSPBootloaderFirmwareEntry PSPDirectoryTableEntryType = 0x01
	// PSPDirectoryTableLevel2Entry denotes an entry that points to PSP Directory table level 2
	PSPDirectoryTableLevel2Entry PSPDirectoryTableEntryType = 0x40
)

// PSPDirectoryTableEntry represents a single entry in PSP Directory Table
// Table 5 in (1)
type PSPDirectoryTableEntry struct {
	Type            PSPDirectoryTableEntryType
	Subprogram      uint8
	ROMId           uint8
	Size            uint32
	LocationOrValue uint64
}

// PSPDirectoryTable represents PSP Directory Table Header with all entries
// Table 3 in (1)
type PSPDirectoryTable struct {
	PSPCookie      uint32
	Checksum       uint32
	TotalEntries   uint32
	AdditionalInfo uint32
	Entries        []PSPDirectoryTableEntry
}

func (p PSPDirectoryTable) String() string {
	var s strings.Builder
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, p.PSPCookie)
	fmt.Fprintf(&s, "PSP Cookie: 0x%x (%s)\n", p.PSPCookie, cookieBytes)
	fmt.Fprintf(&s, "Checksum: %d\n", p.Checksum)
	fmt.Fprintf(&s, "Total Entries: %d\n", p.TotalEntries)
	fmt.Fprintf(&s, "Additional Info: 0x%x\n\n", p.AdditionalInfo)
	fmt.Fprintf(&s, "%-5s | %-8s | %-5s | %-10s | %-10s\n",
		"Type",
		"Subprogram",
		"ROMId",
		"Size",
		"Location/Value")
	fmt.Fprintf(&s, "%s\n", "------------------------------------------------------------------------")
	for _, entry := range p.Entries {
		fmt.Fprintf(&s, "0x%-3x | 0x%-8x | 0x%-3x | %-10d | 0x%-10x\n",
			entry.Type,
			entry.Subprogram,
			entry.ROMId,
			entry.Size,
			entry.LocationOrValue)
	}
	return s.String()
}

// FindPSPDirectoryTable scans firmware for PSPDirectoryTableCookie
// and treats remaining bytes as PSPDirectoryTable
func FindPSPDirectoryTable(image []byte) (*PSPDirectoryTable, uint64, error) {
	// there is no predefined address, search through the whole memory
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, PSPDirectoryTableCookie)

	var offset uint64
	for {
		idx := bytes.Index(image, cookieBytes)
		if idx == -1 {
			break
		}

		table, err := ParsePSPDirectoryTable(bytes.NewBuffer(image[idx:]))
		if err != nil {
			shift := uint64(idx + len(cookieBytes))
			image = image[idx+len(cookieBytes):]
			offset += shift
			continue
		}
		return table, offset + uint64(idx), err
	}
	return nil, 0, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

// ParsePSPDirectoryTable converts input bytes into PSPDirectoryTable
func ParsePSPDirectoryTable(r io.Reader) (*PSPDirectoryTable, error) {
	var table PSPDirectoryTable
	if err := binary.Read(r, binary.LittleEndian, &table.PSPCookie); err != nil {
		return nil, err
	}
	if table.PSPCookie != PSPDirectoryTableCookie && table.PSPCookie != PSPDirectoryTableLevel2Cookie {
		return nil, fmt.Errorf("incorrect cookie: %d", table.PSPCookie)
	}

	if err := binary.Read(r, binary.LittleEndian, &table.Checksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.TotalEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &table.AdditionalInfo); err != nil {
		return nil, err
	}

	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, err := ParsePSPDirectoryTableEntry(r)
		if err != nil {
			return nil, err
		}
		table.Entries = append(table.Entries, *entry)
	}
	return &table, nil
}

// ParsePSPDirectoryTableEntry converts input bytes into PSPDirectoryTableEntry
func ParsePSPDirectoryTableEntry(r io.Reader) (*PSPDirectoryTableEntry, error) {
	var entry PSPDirectoryTableEntry
	if err := binary.Read(r, binary.LittleEndian, &entry.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.Subprogram); err != nil {
		return nil, err
	}

	var flags uint16
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	entry.ROMId = uint8(flags>>14) & 0x3

	if err := binary.Read(r, binary.LittleEndian, &entry.Size); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &entry.LocationOrValue); err != nil {
		return nil, err
	}
	return &entry, nil
}
