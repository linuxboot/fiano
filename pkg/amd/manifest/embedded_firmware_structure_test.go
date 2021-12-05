// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manifest

import (
	"testing"
)

const embeddedFirmwareStructureLength = 0x4A

func TestFindEmbeddedFirmwareStructure(t *testing.T) {
	embeddedFirmwareStructureDataChunk := []byte{
		0xaa, 0x55, 0xaa, 0x55,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0xaa, 0xbb, 0xcc, 0xdd,

		0x11, 0x22, 0x33, 0x44,
		0x00, 0x00, 0x12, 0x34,
		0x55, 0x66, 0x77, 0x88,
		0x00, 0x00, 0x00, 0x00,
		0xbb, 0xee, 0xaa, 0xff,
	}
	for len(embeddedFirmwareStructureDataChunk) < embeddedFirmwareStructureLength {
		embeddedFirmwareStructureDataChunk = append(embeddedFirmwareStructureDataChunk, 0x00)
	}

	dummyPrefix := []byte{0x1, 0x2, 0x3, 0x4}
	firmwareImage := append(dummyPrefix, embeddedFirmwareStructureDataChunk...)
	firmware := newDummyFirmware(firmwareImage, t)
	firmware.addMapping(
		0xfffa0000, 0,
	).addMapping(
		0xfff20000, 0,
	).addMapping(
		0xffe20000, 0,
	).addMapping(
		0xffc20000, 0,
	).addMapping(
		0xff820000, 0,
	).addMapping(
		0xff020000, uint64(len(dummyPrefix)),
	)

	efs, r, err := FindEmbeddedFirmwareStructure(firmware)
	if err != nil {
		t.Fatalf("finding embedded firmware structure failed: '%v'", err)
	}
	if r.Offset != uint64(len(dummyPrefix)) {
		t.Errorf("returned offset: '%d', expected: '%d'", r.Offset, len(dummyPrefix))
	}
	if r.Length != embeddedFirmwareStructureLength {
		t.Errorf("returned length: '%d', expected: '%d'", r.Length, embeddedFirmwareStructureLength)
	}
	if efs == nil {
		t.Fatalf("result embedded firmware structure is nil")
	}
	if efs.Signature != EmbeddedFirmwareStructureSignature {
		t.Errorf("actual EFS.signature: '%X', expected: '%X'", efs.Signature, EmbeddedFirmwareStructureSignature)
	}
	if efs.PSPDirectoryTablePointer != 0xddccbbaa {
		t.Errorf("actual efs.PSPDirectoryTablePointer: '%X', expected: '%X'", efs.PSPDirectoryTablePointer, 0xddccbbaa)
	}
	if efs.BIOSDirectoryTableFamily17hModels00h0FhPointer != 0x44332211 {
		t.Errorf("actual EFS.BIOSDirectoryTableFamily17hModels00h0FhPointer: '%X', expected: '%X'", efs.BIOSDirectoryTableFamily17hModels00h0FhPointer, 0x44332211)
	}
	if efs.BIOSDirectoryTableFamily17hModels10h1FhPointer != 0x34120000 {
		t.Errorf("actual EFS.BIOSDirectoryTableFamily17hModels10h1FhPointer: '%X', expected: '%X'", efs.BIOSDirectoryTableFamily17hModels10h1FhPointer, 0x34120000)
	}
	if efs.BIOSDirectoryTableFamily17hModels30h3FhPointer != 0x88776655 {
		t.Errorf("actual EFS.BIOSDirectoryTableFamily17hModels30h3FhPointer: '%X', expected: '%X'", efs.BIOSDirectoryTableFamily17hModels30h3FhPointer, 0x88776655)
	}
	if efs.BIOSDirectoryTableFamily17hModels60h3FhPointer != 0xffaaeebb {
		t.Errorf("actual EFS.BIOSDirectoryTableFamily17hModels60h3FhPointer: '%X', expected: '%X'", efs.BIOSDirectoryTableFamily17hModels60h3FhPointer, 0xffaaeebb)
	}
}

type dummyFirmware struct {
	image []byte
	t     *testing.T

	physToOffset map[uint64]uint64
	offsetToPhys map[uint64]uint64
}

func newDummyFirmware(image []byte, t *testing.T) *dummyFirmware {
	return &dummyFirmware{
		image:        image,
		t:            t,
		physToOffset: make(map[uint64]uint64),
		offsetToPhys: make(map[uint64]uint64),
	}
}

func (f *dummyFirmware) addMapping(physAddr, offset uint64) *dummyFirmware {
	f.physToOffset[physAddr] = offset
	f.offsetToPhys[offset] = physAddr
	return f
}

func (f *dummyFirmware) ImageBytes() []byte {
	return f.image
}

func (f *dummyFirmware) PhysAddrToOffset(physAddr uint64) uint64 {
	result, found := f.physToOffset[physAddr]
	if !found {
		f.t.Fatalf("physical address '%d' could not be mapped", physAddr)
	}
	return result
}

func (f *dummyFirmware) OffsetToPhysAddr(offset uint64) uint64 {
	result, found := f.offsetToPhys[offset]
	if !found {
		f.t.Fatalf("image offset '%d' could not be mapped", offset)
	}
	return result
}
