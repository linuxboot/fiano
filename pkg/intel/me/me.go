// Copyright 2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package me

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// LegacyFlashPartitionTableHeader describes the old flash partition table header
// in Intel ME binaries.
type LegacyFlashPartitionTableHeader struct {
	Padding        [16]uint8 // 16 zeros
	Marker         uint32    // Always $FPT
	NumFptEntries  uint32
	HeaderVersion  uint8
	EntryVersion   uint8
	HeaderLength   uint8 // Usually 0x30
	HeaderChecksum uint8
	TicksToAdd     uint16
	TokensToAdd    uint16
	UMASize        uint32
	Flags          uint32
}

func (h LegacyFlashPartitionTableHeader) String() string {
	var b strings.Builder
	b.WriteString("Flash partition table:\n")
	fmt.Fprintf(&b, " Entries       : %d\n", h.NumFptEntries)
	fmt.Fprintf(&b, " HeaderVersion : 0x%x\n", h.HeaderVersion)
	fmt.Fprintf(&b, " EntryVersion  : 0x%x\n", h.EntryVersion)
	fmt.Fprintf(&b, " HeaderLength  : 0x%x\n", h.HeaderLength)
	fmt.Fprintf(&b, " HeaderChecksum: 0x%x\n", h.HeaderChecksum)
	fmt.Fprintf(&b, " TicksToAdd    : 0x%x\n", h.TicksToAdd)
	fmt.Fprintf(&b, " TokensToAdd   : 0x%x\n", h.TokensToAdd)
	fmt.Fprintf(&b, " UMASize       : 0x%x\n", h.UMASize)
	fmt.Fprintf(&b, " Flags         : 0x%x\n", h.Flags)

	return b.String()
}

// FlashPartitionTableHeader describes the new flash partition table header
// in Intel ME binaries.
type FlashPartitionTableHeader struct {
	Marker             uint32 // Always $FPT
	NumFptEntries      uint32
	HeaderVersion      uint8 // Only support 2.0
	EntryVersion       uint8
	HeaderLength       uint8 // Usually 0x20
	HeaderChecksum     uint8
	TicksToAdd         uint16
	TokensToAdd        uint16
	UMASizeOrReserved  uint32
	FlashLayoutOrFlags uint32
	// Not Present in ME version 7
	FitcMajor  uint16
	FitcMinor  uint16
	FitcHotfix uint16
	FitcBuild  uint16
}

func (h FlashPartitionTableHeader) String() string {
	var b strings.Builder

	b.WriteString("Flash partition table:\n")
	fmt.Fprintf(&b, " Entries            : %d\n", h.NumFptEntries)
	fmt.Fprintf(&b, " HeaderVersion      : 0x%x\n", h.HeaderVersion)
	fmt.Fprintf(&b, " EntryVersion       : 0x%x\n", h.EntryVersion)
	fmt.Fprintf(&b, " HeaderLength       : 0x%x\n", h.HeaderLength)
	fmt.Fprintf(&b, " HeaderChecksum     : 0x%x\n", h.HeaderChecksum)
	fmt.Fprintf(&b, " TicksToAdd         : 0x%x\n", h.TicksToAdd)
	fmt.Fprintf(&b, " TokensToAdd        : 0x%x\n", h.TokensToAdd)
	fmt.Fprintf(&b, " UMASizeOrReserved  : 0x%x\n", h.UMASizeOrReserved)
	fmt.Fprintf(&b, " FlashLayoutOrFlags : 0x%x\n", h.FlashLayoutOrFlags)
	fmt.Fprintf(&b, " Fitc Version       : %d.%d.%d.%d\n", h.FitcMajor, h.FitcMinor, h.FitcHotfix, h.FitcBuild)

	return b.String()
}

// FlashPartitionTableEntry describes information of a flash partition table entry.
type FlashPartitionTableEntry struct {
	Name           [4]uint8
	Owner          [4]uint8
	Offset         uint32
	Length         uint32
	StartTokens    uint32
	MaxTokens      uint32
	ScratchSectors uint32
	Flags          uint32
}

func (e FlashPartitionTableEntry) String() string {
	var b strings.Builder
	b.WriteString("Flash partition entry:\n")
	fmt.Fprintf(&b, " Name          : %s\n", []byte{e.Name[0], e.Name[1], e.Name[2], e.Name[3]})
	fmt.Fprintf(&b, " Owner         : %s\n", []byte{e.Owner[0], e.Owner[1], e.Owner[2], e.Owner[3]})
	fmt.Fprintf(&b, " Offset        : 0x%x\n", e.Offset)
	fmt.Fprintf(&b, " Length        : 0x%x\n", e.Length)
	fmt.Fprintf(&b, " StartTokens   : 0x%x\n", e.StartTokens)
	fmt.Fprintf(&b, " MaxTokens     : 0x%x\n", e.MaxTokens)
	fmt.Fprintf(&b, " ScratchSectors: 0x%x\n", e.ScratchSectors)
	fmt.Fprintf(&b, " Flags         : 0x%x\n", e.Flags)

	if e.Flags>>24 == 0xff {
		b.WriteString(" Valid         : No\n")
	} else {
		b.WriteString(" Valid         : yes\n")
	}
	if e.Flags&1 > 0 {
		b.WriteString(" Partition     : Data\n")
	} else {
		b.WriteString(" Partition     : Code\n")
	}

	return b.String()
}

// IntelME abstracts the ME/CSME/SPS firmware found on intel platforms
type IntelME struct {
	hdr        *FlashPartitionTableHeader
	legacyhdr  *LegacyFlashPartitionTableHeader
	legacy     bool
	partitions []FlashPartitionTableEntry
	image      []byte
	// Offset in image to $FPT
	fptoffset uint32
}

// ParseIntelFirmware parses the Intel firmware image by uefi.Firmware interface`
func ParseIntelFirmware(firmware uefi.Firmware) (*IntelME, error) {
	uefi, err := ParseIntelFirmwareBytes(firmware.Buf())
	if err != nil {
		return nil, fmt.Errorf("unable to get the content of file: %v", err)
	}

	return uefi, nil
}

// ParseIntelFirmwareBytes parses the Intel firmware image from bytes
func ParseIntelFirmwareBytes(imageBytes []byte) (*IntelME, error) {
	legacy := false
	fptoffset := -1
	// Search for the Flash partition table
	for i := 0; i < len(imageBytes); i += 0x1000 {

		// New Header
		if bytes.HasPrefix(imageBytes[i:], []byte(`$FPT`)) {
			fptoffset = i
			break
		}
		// Legacy Header
		if bytes.HasPrefix(imageBytes[i:], append(make([]byte, 16), []byte(`$FPT`)...)) {
			legacy = true
			fptoffset = i
			break
		}
	}
	if fptoffset == -1 {
		return nil, fmt.Errorf("no FlashPartitionTable found")
	}

	me := &IntelME{image: imageBytes, legacy: legacy, fptoffset: uint32(fptoffset)}
	reader := bytes.NewReader(imageBytes[fptoffset:])
	offset := 0
	entries := 0

	if legacy {
		if err := binary.Read(reader, binary.LittleEndian, &me.legacyhdr); err != nil {
			return nil, err
		}
		if me.legacyhdr.HeaderVersion != 0x20 {
			return nil, fmt.Errorf("unsupported header version. Got 0x%x", me.legacyhdr.HeaderVersion)
		}
		if int(me.legacyhdr.HeaderLength) > len(imageBytes)-fptoffset {
			return nil, fmt.Errorf("invalid header length. Got 0x%x", me.legacyhdr.HeaderLength)
		}
		offset = int(me.legacyhdr.HeaderLength)
		entries = int(me.legacyhdr.NumFptEntries)
	} else {
		if err := binary.Read(reader, binary.LittleEndian, &me.hdr); err != nil {
			return nil, err
		}
		if me.hdr.HeaderVersion != 0x20 {
			return nil, fmt.Errorf("unsupported header version. Got 0x%x", me.hdr.HeaderVersion)
		}
		if int(me.hdr.HeaderLength) > len(imageBytes)-fptoffset {
			return nil, fmt.Errorf("invalid header length. Got 0x%x", me.hdr.HeaderLength)
		}
		offset = int(me.hdr.HeaderLength)
		entries = int(me.hdr.NumFptEntries)
	}

	reader = bytes.NewReader(imageBytes[fptoffset+offset:])

	for i := 0; i < entries; i++ {
		var e FlashPartitionTableEntry
		if err := binary.Read(reader, binary.LittleEndian, &e); err != nil {
			return nil, err
		}
		me.partitions = append(me.partitions, e)

	}

	return me, nil
}

// ImageBytes just returns the image as `[]byte`.
func (m *IntelME) ImageBytes() []byte {
	return m.image
}

// PrintInfo prints the ME partitions in human readable format
func (m *IntelME) PrintInfo() string {
	ret := ""
	if m.legacy {
		ret += m.legacyhdr.String()
	} else {
		ret += m.hdr.String()
	}
	for i := range m.partitions {
		ret += m.partitions[i].String()
	}
	return ret
}

// WritePartition writes new data into specified partition.
// Must be equal in size to current parition
func (m *IntelME) WritePartition(id string, data []byte) (err error) {
	for i := range m.partitions {
		name := m.partitions[i].Name
		if string(bytes.Trim([]byte{name[0], name[1], name[2], name[3]}, "\x00")) == id {
			if uint32(len(data)) != m.partitions[i].Length {
				return fmt.Errorf("invalid length")
			}
			m.image = append(append(m.image[:m.partitions[i].Offset+m.fptoffset], data...),
				m.image[m.partitions[i].Offset+m.partitions[i].Length+m.fptoffset:]...)
			return nil
		}
	}
	return fmt.Errorf("not found")
}

// ReadPartition reads data from specified partition.
func (m *IntelME) ReadPartition(id string) (data []byte, err error) {
	for i := range m.partitions {
		name := m.partitions[i].Name
		if string(bytes.Trim([]byte{name[0], name[1], name[2], name[3]}, "\x00")) == id {
			data = m.image[m.partitions[i].Offset+m.fptoffset : m.partitions[i].Offset+m.partitions[i].Length+m.fptoffset]
			return data, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

// LsPartitions list all partition found in image
func (m *IntelME) LsPartitions() []string {
	var part []string
	for i := range m.partitions {
		name := m.partitions[i].Name
		part = append(part, string(bytes.Trim([]byte{name[0], name[1], name[2], name[3]}, "\x00")))
	}
	return part
}
