// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"fmt"

	bytes2 "github.com/linuxboot/fiano/pkg/bytes"
)

// Firmware is an abstraction of a firmware image, obtained for example via flashrom
type Firmware interface {
	ImageBytes() []byte
	PhysAddrToOffset(physAddr uint64) uint64
	OffsetToPhysAddr(offset uint64) uint64
}

type BIOSDir struct {
	BIOSDirectoryLevel1      *BIOSDirectoryTable
	BIOSDirectoryLevel1Range bytes2.Range
	BIOSDirectoryLevel2      *BIOSDirectoryTable
	BIOSDirectoryLevel2Range bytes2.Range
}

type PSPDir struct {
	PSPDirectoryLevel1      *PSPDirectoryTable
	PSPDirectoryLevel1Range bytes2.Range
	PSPDirectoryLevel2      *PSPDirectoryTable
	PSPDirectoryLevel2Range bytes2.Range
}

// PSPFirmware contains essential parts of the AMD's PSP firmware internals
type PSPFirmware struct {
	EmbeddedFirmware      EmbeddedFirmwareStructure
	EmbeddedFirmwareRange bytes2.Range
	BIOSDirectories       []BIOSDir
	PSPDirectories        []PSPDir
}

// AMDFirmware represents an instance of firmware that exposes AMD specific
// meatadata and structure.
type AMDFirmware struct {
	// firmware is a reference to a generic firmware interface
	firmware Firmware

	// pspFirmware is a reference to PSPFirmware structure. It is built at
	// construction time and not exported.
	pspFirmware *PSPFirmware
}

// Firmware returns the internal reference to Firmawre interface
func (a *AMDFirmware) Firmware() Firmware {
	return a.firmware
}

// PSPFirmware returns the PSPFirmware reference held by the AMDFirmware object
func (a *AMDFirmware) PSPFirmware() *PSPFirmware {
	return a.pspFirmware
}

// parsePSPFirmware parses input firmware as PSP firmware image and
// collects Embedded firmware, PSP directory and BIOS directory structures
func parsePSPFirmware(firmware Firmware) (*PSPFirmware, error) {
	image := firmware.ImageBytes()

	var result PSPFirmware
	efs, r, err := FindEmbeddedFirmwareStructure(firmware)
	if err != nil {
		return nil, err
	}
	result.EmbeddedFirmware = *efs
	result.EmbeddedFirmwareRange = r

	var pspDirectoryLevel1 *PSPDirectoryTable
	var pspDirectoryLevel1Range bytes2.Range
	if efs.PSPDirectoryTablePointer != 0 && efs.PSPDirectoryTablePointer < uint32(len(image)) {
		var length uint64
		pspDirectoryLevel1, length, err = ParsePSPDirectoryTable(image[efs.PSPDirectoryTablePointer:])
		if err == nil {
			pspDirectoryLevel1Range.Offset = uint64(efs.PSPDirectoryTablePointer)
			pspDirectoryLevel1Range.Length = length
		}
	}
	if pspDirectoryLevel1 == nil {
		pspDirectoryLevel1, pspDirectoryLevel1Range, _ = FindPSPDirectoryTable(image)
	}
	if pspDirectoryLevel1 != nil {
		result.PSPDirectories = []PSPDir{}
		result.PSPDirectories = append(result.PSPDirectories, PSPDir{})

		result.PSPDirectories[0].PSPDirectoryLevel1 = pspDirectoryLevel1
		result.PSPDirectories[0].PSPDirectoryLevel1Range = pspDirectoryLevel1Range

		for _, entry := range pspDirectoryLevel1.Entries {
			if entry.Type != PSPDirectoryTableLevel2Entry {
				continue
			}
			if entry.LocationOrValue != 0 && entry.LocationOrValue < uint64(len(image)) {
				pspDirectoryLevel2, length, err := ParsePSPDirectoryTable(image[entry.LocationOrValue:])
				if err == nil {
					result.PSPDirectories[0].PSPDirectoryLevel2 = pspDirectoryLevel2
					result.PSPDirectories[0].PSPDirectoryLevel2Range.Offset = entry.LocationOrValue
					result.PSPDirectories[0].PSPDirectoryLevel2Range.Length = length
				}
			}
			break
		}
	}

	result.BIOSDirectories = []BIOSDir{}
	result.BIOSDirectories = append(result.BIOSDirectories, BIOSDir{})

	var biosDirectoryLevel1 *BIOSDirectoryTable
	var biosDirectoryLevel1Range bytes2.Range

	biosDirectoryOffsets := []uint32{
		efs.BIOSDirectoryTableFamily17hModels00h0FhPointer,
		efs.BIOSDirectoryTableFamily17hModels10h1FhPointer,
		efs.BIOSDirectoryTableFamily17hModels30h3FhPointer,
		efs.BIOSDirectoryTableFamily17hModels60h3FhPointer,
	}
	for _, offset := range biosDirectoryOffsets {
		if offset == 0 || int(offset) > len(image) {
			continue
		}
		var length uint64
		biosDirectoryLevel1, length, err = ParseBIOSDirectoryTable(image[offset:])
		if err != nil {
			continue
		}
		biosDirectoryLevel1Range.Offset = uint64(offset)
		biosDirectoryLevel1Range.Length = length
		break
	}

	if biosDirectoryLevel1 == nil {
		biosDirectoryLevel1, biosDirectoryLevel1Range, _ = FindBIOSDirectoryTable(image)
	}

	if biosDirectoryLevel1 != nil {
		result.BIOSDirectories[0].BIOSDirectoryLevel1 = biosDirectoryLevel1
		result.BIOSDirectories[0].BIOSDirectoryLevel1Range = biosDirectoryLevel1Range

		for _, entry := range biosDirectoryLevel1.Entries {
			if entry.Type != BIOSDirectoryTableLevel2Entry {
				continue
			}
			if entry.SourceAddress != 0 && entry.SourceAddress < uint64(len(image)) {
				biosDirectoryLevel2, length, err := ParseBIOSDirectoryTable(image[entry.SourceAddress:])
				if err == nil {
					result.BIOSDirectories[0].BIOSDirectoryLevel2 = biosDirectoryLevel2
					result.BIOSDirectories[0].BIOSDirectoryLevel2Range.Offset = entry.SourceAddress
					result.BIOSDirectories[0].BIOSDirectoryLevel2Range.Length = length
				}
			}
			break
		}
	}

	return &result, nil
}

// NewAMDFirmware returns an AMDFirmware structure or an error if internal firmare structures cannot be parsed
func NewAMDFirmware(firmware Firmware) (*AMDFirmware, error) {
	pspFirmware, err := parsePSPFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not construct AMDFirmware, cannot parse PSP firmware: %w", err)
	}
	return &AMDFirmware{firmware: firmware, pspFirmware: pspFirmware}, nil

}
