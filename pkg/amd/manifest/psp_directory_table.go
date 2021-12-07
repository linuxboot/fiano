// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	bytes2 "github.com/linuxboot/fiano/pkg/bytes"
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

const PSPDirectoryTableEntrySize = 16

// PSPDirectoryTableHeader represents a BIOS Directory Table Header
// Tables 3&4 from (1)
type PSPDirectoryTableHeader struct {
	PSPCookie      uint32
	Checksum       uint32
	TotalEntries   uint32
	AdditionalInfo uint32
}

// PSPDirectoryTable represents PSP Directory Table Header with all entries
// Table 5 in (1)
type PSPDirectoryTable struct {
	PSPDirectoryTableHeader

	Entries []PSPDirectoryTableEntry
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
func FindPSPDirectoryTable(image []byte) (*PSPDirectoryTable, bytes2.Range, error) {
	// there is no predefined address, search through the whole memory
	cookieBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(cookieBytes, PSPDirectoryTableCookie)

	var offset uint64
	for {
		idx := bytes.Index(image, cookieBytes)
		if idx == -1 {
			break
		}

		table, length, err := ParsePSPDirectoryTable(image[idx:])
		if err != nil {
			shift := uint64(idx + len(cookieBytes))
			image = image[idx+len(cookieBytes):]
			offset += shift
			continue
		}
		return table, bytes2.Range{Offset: offset + uint64(idx), Length: length}, err
	}
	return nil, bytes2.Range{}, fmt.Errorf("PSPDirectoryTable is not found")
}

// ParsePSPDirectoryTable converts input bytes into PSPDirectoryTable
func ParsePSPDirectoryTable(data []byte) (*PSPDirectoryTable, uint64, error) {
	var table PSPDirectoryTable
	var totalLength uint64

	r := bytes.NewBuffer(data)
	if err := readAndCountSize(r, binary.LittleEndian, &table.PSPCookie, &totalLength); err != nil {
		return nil, 0, err
	}
	if table.PSPCookie != PSPDirectoryTableCookie && table.PSPCookie != PSPDirectoryTableLevel2Cookie {
		return nil, 0, fmt.Errorf("incorrect cookie: %d", table.PSPCookie)
	}
	if err := readAndCountSize(r, binary.LittleEndian, &table.Checksum, &totalLength); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &table.TotalEntries, &totalLength); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &table.AdditionalInfo, &totalLength); err != nil {
		return nil, 0, err
	}

	sizeRequired := uint64(table.TotalEntries) * PSPDirectoryTableEntrySize
	if uint64(r.Len()) < sizeRequired {
		return nil, 0, fmt.Errorf("not enough data, required: %d, actual: %d", sizeRequired+totalLength, len(data))
	}

	for idx := uint32(0); idx < table.TotalEntries; idx++ {
		entry, length, err := ParsePSPDirectoryTableEntry(r)
		if err != nil {
			return nil, 0, err
		}
		totalLength += length
		table.Entries = append(table.Entries, *entry)
	}
	return &table, totalLength, nil
}

// ParsePSPDirectoryTableEntry converts input bytes into PSPDirectoryTableEntry
func ParsePSPDirectoryTableEntry(r io.Reader) (*PSPDirectoryTableEntry, uint64, error) {
	var entry PSPDirectoryTableEntry
	var length uint64

	if err := readAndCountSize(r, binary.LittleEndian, &entry.Type, &length); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &entry.Subprogram, &length); err != nil {
		return nil, 0, err
	}

	var flags uint16
	if err := readAndCountSize(r, binary.LittleEndian, &flags, &length); err != nil {
		return nil, 0, err
	}
	entry.ROMId = uint8(flags>>14) & 0x3

	if err := readAndCountSize(r, binary.LittleEndian, &entry.Size, &length); err != nil {
		return nil, 0, err
	}
	if err := readAndCountSize(r, binary.LittleEndian, &entry.LocationOrValue, &length); err != nil {
		return nil, 0, err
	}
	return &entry, length, nil
}
