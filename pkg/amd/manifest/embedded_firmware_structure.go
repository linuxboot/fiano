package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Refer to: AMD Platform Security Processor BIOS Architecture Design Guide for AMD Family 17h and Family 19h
// Processors (NDA), Publication # 55758 Revision: 1.11 Issue Date: August 2020 (1)

const EmbeddedFirmwareStructureSignature = 0x55aa55aa

type EmbeddedFirmwareStructure struct {
	Signature                uint32
	Required1                [16]byte
	PSPDirectoryTablePointer uint32

	BIOSDirectoryTableFamily17hModels00h0FhPointer uint32
	BIOSDirectoryTableFamily17hModels10h1FhPointer uint32
	BIOSDirectoryTableFamily17hModels30h3FhPointer uint32
}

func FindEmbeddedFirmwareStructure(firmware Firmware) (*EmbeddedFirmwareStructure, uint64, error) {
	var addresses = []uint64{
		0xfffa0000,
		0xfff20000,
		0xffe20000,
		0xffc20000,
		0xff820000,
		0xff020000,
	}

	image := firmware.ImageBytes()

	for _, addr := range addresses {
		offset := firmware.PhysAddrToOffset(addr)
		if offset+4 > uint64(len(image)) {
			continue
		}

		actualSignature := binary.LittleEndian.Uint32(image[offset:])
		if actualSignature == EmbeddedFirmwareStructureSignature {
			result, err := ParseEmbeddedFirmwareStructure(bytes.NewBuffer(image[offset:]))
			return result, addr, err
		}
	}
	return nil, 0, fmt.Errorf("EmbeddedFirmwareStructure is not found")
}

func ParseEmbeddedFirmwareStructure(r io.Reader) (*EmbeddedFirmwareStructure, error) {
	var result EmbeddedFirmwareStructure
	if err := binary.Read(r, binary.LittleEndian, &result); err != nil {
		return nil, err
	}

	if result.Signature != EmbeddedFirmwareStructureSignature {
		return nil, fmt.Errorf("incorrect signature: %d", result.Signature)
	}

	return &result, nil
}
