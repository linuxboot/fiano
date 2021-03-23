package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

const PSPDirectoryTableCookie = 0x24505350       // "$PSP"
const PSPDirectoryTableLevel2Cookie = 0x24504c32 // $PL2

type PSPDirectoryTableEntryType uint8

const (
	AMDPublicKeyEntry            PSPDirectoryTableEntryType = 0x00
	BIOSRTMEntry                 PSPDirectoryTableEntryType = 0x07
	PSPDirectoryTableLevel2Entry PSPDirectoryTableEntryType = 0x40
)

// PSPDirectoryTableEntry represents a single entry in PSP Directory Table
// Table 5 from (1)
type PSPDirectoryTableEntry struct {
	Type            PSPDirectoryTableEntryType
	Subprogram      uint8
	ROMId           uint8
	Size            uint32
	LocationOrValue uint64
}

// PSPDirectoryTableEntry represents PSP Directory Table Header with all entries
// Table 3 from (1)
type PSPDirectoryTable struct {
	PSPCookie      uint32
	Checksum       uint32
	TotalEntries   uint32
	AdditionalInfo uint32
	Entries        []PSPDirectoryTableEntry
}

// FindPSPDirectoryTable scans firmware for PSPDirectoryTableCookie
// and treats remaining bytes as BIOSDirectoryTable
func FindPSPDirectoryTable(firmware Firmware) (*PSPDirectoryTable, uint64, error) {
	// there is no predefined address, search through the whole memory
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, PSPDirectoryTableCookie)

	image := firmware.ImageBytes()

	var offset uint64
	for {
		idx := bytes.Index(image, cookieBytes)
		if idx == -1 {
			break
		}

		table, err := ParsePSPDirectoryTable(bytes.NewBuffer(image[idx:]))
		offset += uint64(idx)
		if err != nil {
			image = image[idx+len(cookieBytes):]
			continue
		}

		return table, firmware.OffsetToPhysAddr(offset), err
	}

	return nil, 0, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

// ParsePSPDirectoryTable converts input bytes into PSPDirectoryTable
func ParsePSPDirectoryTable(r io.Reader) (*PSPDirectoryTable, error) {
	var table PSPDirectoryTable
	if err := binary.Read(r, binary.BigEndian, &table.PSPCookie); err != nil {
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
