// Copyright 2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package me

import (
	"fmt"
	"strings"
)

// LegacyFlashPartitionTableHeader describes the old flash partition table header
// in Intel ME binaries.
type LegacyFlashPartitionTableHeader struct {
	Padding        [16]byte // 16 zeros
	Marker         [4]byte  // Always $FPT
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
	Marker             [4]byte // Always $FPT
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

type name [4]byte

func (n *name) String() string {
	return string(n[:])
}

// FlashPartitionTableEntry describes information of a flash partition table entry.
type FlashPartitionTableEntry struct {
	Name           name
	Owner          name
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
	fmt.Fprintf(&b, " Name          : %s\n", e.Name.String())
	fmt.Fprintf(&b, " Owner         : %s\n", e.Owner.String())
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
}
