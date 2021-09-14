// Copyright 2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package me

import (
	"bytes"
	"encoding/binary"
	"io"
)

var (
	Signature = [4]byte{0x24, 0x46, 0x50, 0x54}
)

func parseLegacyFlashPartitionTableHeader(r io.Reader) (*LegacyFlashPartitionTableHeader, error) {
	var header LegacyFlashPartitionTableHeader
	var scrap [12]byte
	if err := binary.Read(r, binary.LittleEndian, &scrap); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.Marker); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.NumFptEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.HeaderVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.EntryVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.HeaderLength); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.HeaderChecksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.TicksToAdd); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.TokensToAdd); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.UMASize); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.Flags); err != nil {
		return nil, err
	}
	return &header, nil

}

func parseFlashPartitionTableHeader(r io.Reader) (*FlashPartitionTableHeader, error) {
	var header FlashPartitionTableHeader
	// Set Signature
	header.Marker = Signature

	if err := binary.Read(r, binary.LittleEndian, &header.NumFptEntries); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.HeaderVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.EntryVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.HeaderLength); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.HeaderChecksum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.TicksToAdd); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.TokensToAdd); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.UMASizeOrReserved); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.FlashLayoutOrFlags); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.FitcMajor); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.FitcMinor); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.FitcHotfix); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &header.FitcBuild); err != nil {
		return nil, err
	}

	return &header, nil
}

func parseEntry(r io.Reader) (*FlashPartitionTableEntry, error) {
	var entry FlashPartitionTableEntry
	if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ParseIntelFirmware parses the Intel firmware image by uefi.Firmware interface`
func ParseIntelME(r io.Reader) (*IntelME, error) {
	var me IntelME
	me.legacy = false
	var numEntries uint32

	// Read first 4 byte, we catch the marker as prefix or suffix
	var markerarea [4]byte
	if err := binary.Read(r, binary.LittleEndian, &markerarea); err != nil {
		return nil, err
	}

	// Check on new header
	if bytes.HasPrefix(markerarea[:], Signature[:]) {
		hdr, err := parseFlashPartitionTableHeader(r)
		if err != nil {
			return nil, err
		}
		me.hdr = hdr
		numEntries = hdr.NumFptEntries
	} else {
		me.legacy = true
		hdr, err := parseLegacyFlashPartitionTableHeader(r)
		if err != nil {
			return nil, err
		}
		me.legacyhdr = hdr
		numEntries = hdr.NumFptEntries
	}

	partitions := make([]FlashPartitionTableEntry, 0)
	for i := uint32(0); i < numEntries; i++ {
		entry, err := parseEntry(r)
		if err != nil {
			return nil, err
		}
		partitions = append(partitions, *entry)
	}
	me.partitions = partitions
	return &me, nil
}
