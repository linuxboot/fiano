package manifest

import (
	"bytes"
	bytes2 "github.com/9elements/converged-security-suite/v2/pkg/bytes"
)

// Firmware is an abstraction of a firmware image, obtained for example via flashrom
type Firmware interface {
	ImageBytes() []byte
	PhysAddrToOffset(physAddr uint64) uint64
	OffsetToPhysAddr(offset uint64) uint64
}

// PSPFirmware contains essential parts of the AMD's PSP firmware internals
type PSPFirmware struct {
	EmbeddedFirmware      EmbeddedFirmwareStructure
	EmbeddedFirmwareRange bytes2.Range

	PSPDirectoryLevel1      *PSPDirectoryTable
	PSPDirectoryLevel1Range bytes2.Range
	PSPDirectoryLevel2      *PSPDirectoryTable
	PSPDirectoryLevel2Range bytes2.Range

	BIOSDirectoryLevel1      *BIOSDirectoryTable
	BIOSDirectoryLevel1Range bytes2.Range
	BIOSDirectoryLevel2      *BIOSDirectoryTable
	BIOSDirectoryLevel2Range bytes2.Range
}

// ParsePSPFirmware parses input firmware as PSP firmware image and
// collects Embedded firmware, PSP directory and BIOS directory structures
func ParsePSPFirmware(firmware Firmware) (*PSPFirmware, error) {
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
		pspDirectoryLevel1, length, err = ParsePSPDirectoryTable(bytes.NewBuffer(image[efs.PSPDirectoryTablePointer:]))
		if err == nil {
			pspDirectoryLevel1Range.Offset = uint64(efs.PSPDirectoryTablePointer)
			pspDirectoryLevel1Range.Length = length
		}
	}
	if pspDirectoryLevel1 == nil {
		pspDirectoryLevel1, pspDirectoryLevel1Range, _ = FindPSPDirectoryTable(image)
	}
	if pspDirectoryLevel1 != nil {
		result.PSPDirectoryLevel1 = pspDirectoryLevel1
		result.PSPDirectoryLevel1Range = pspDirectoryLevel1Range

		for _, entry := range pspDirectoryLevel1.Entries {
			if entry.Type != PSPDirectoryTableLevel2Entry {
				continue
			}
			if entry.LocationOrValue != 0 && entry.LocationOrValue < uint64(len(image)) {
				pspDirectoryLevel2, length, err := ParsePSPDirectoryTable(bytes.NewBuffer(image[entry.LocationOrValue:]))
				if err == nil {
					result.PSPDirectoryLevel2 = pspDirectoryLevel2
					result.PSPDirectoryLevel2Range.Offset = entry.LocationOrValue
					result.PSPDirectoryLevel2Range.Length = length
				}
			}
			break
		}
	}

	var biosDirectoryLevel1 *BIOSDirectoryTable
	var biosDirectoryLevel1Range bytes2.Range

	biosDirectoryOffsets := []uint32{
		efs.BIOSDirectoryTableFamily17hModels00h0FhPointer,
		efs.BIOSDirectoryTableFamily17hModels10h1FhPointer,
		efs.BIOSDirectoryTableFamily17hModels30h3FhPointer,
		efs.BIOSDirectoryTableFamily17hModels60h3FhPointer,
	}
	for _, offset := range biosDirectoryOffsets {
		if offset == 0 {
			continue
		}
		var length uint64
		biosDirectoryLevel1, length, err = ParseBIOSDirectoryTable(bytes.NewBuffer(image[offset:]))
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
		result.BIOSDirectoryLevel1 = biosDirectoryLevel1
		result.BIOSDirectoryLevel1Range = biosDirectoryLevel1Range

		for _, entry := range biosDirectoryLevel1.Entries {
			if entry.Type != BIOSDirectoryTableLevel2Entry {
				continue
			}
			if entry.SourceAddress != 0 && entry.SourceAddress < uint64(len(image)) {
				biosDirectoryLevel2, length, err := ParseBIOSDirectoryTable(bytes.NewBuffer(image[entry.SourceAddress:]))
				if err == nil {
					result.BIOSDirectoryLevel2 = biosDirectoryLevel2
					result.BIOSDirectoryLevel2Range.Offset = entry.SourceAddress
					result.BIOSDirectoryLevel2Range.Length = length
				}
			}
			break
		}
	}

	return &result, nil
}
