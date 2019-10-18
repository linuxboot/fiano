// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// CreateFV creates a firmware volume at given offset
type CreateFV struct {
	AbsOffset uint64
	Size      uint64
	Name      guid.GUID

	offset uint64
	found  bool
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *CreateFV) Run(f uefi.Firmware) error {
	err := f.Apply(v)
	if err != nil {
		return err
	}
	if !v.found {
		return fmt.Errorf("Cannot create FV at %#x (+%#x) no BIOS region found", v.AbsOffset, v.Size)
	}
	return nil
}

// Visit applies the Remove visitor to any Firmware type.
func (v *CreateFV) Visit(f uefi.Firmware) error {
	if v.found {
		return nil
	}
	var offset, end uint64
	switch f := f.(type) {
	case *uefi.BIOSRegion:
		if f.FRegion != nil {
			offset = uint64(f.FRegion.BaseOffset())
			end = uint64(f.FRegion.EndOffset())
		}
		if v.AbsOffset < offset {
			return fmt.Errorf("Cannot create FV at %#x, BIOS region starts at %#x", v.AbsOffset, offset)
		}
		if v.AbsOffset+v.Size >= end {
			return fmt.Errorf("Cannot create FV ending at %#x (%#x + %#x), BIOS region ends at %#x", v.AbsOffset+v.Size, v.AbsOffset, v.Size, end)
		}

		// Manually visit children, we want the index
		idx := -1
		var bp *uefi.BIOSPadding
	L:
		for i, e := range f.Elements {
			switch f := e.Value.(type) {
			case *uefi.BIOSPadding:
				bp = f
				bpOffset := offset + f.Offset
				bpEnd := bpOffset + uint64(len(f.Buf()))
				if v.AbsOffset >= bpOffset && v.AbsOffset+v.Size <= bpEnd {

					idx = i
					break L
				}
			}
		}

		if idx == -1 {
			return fmt.Errorf("Cannot create FV at %#x (+%#x) no matching BIOS Pad found", v.AbsOffset, v.Size)
		}
		v.found = true
		fv, err := createEmptyFirmwareVolume(v.AbsOffset-offset, v.Size, &v.Name)
		if err != nil {
			return err
		}
		return insertFVinBP(f, v.AbsOffset-offset, bp, idx, fv)
	}

	return f.ApplyChildren(v)
}

func insertFVinBP(br *uefi.BIOSRegion, offset uint64, bp *uefi.BIOSPadding, idx int, fv *uefi.FirmwareVolume) error {
	// Copy the Elements before the modified BIOS Pad
	newElements := make([]*uefi.TypedFirmware, idx, len(br.Elements))
	copy(newElements, br.Elements[:idx])

	bpBuf := bp.Buf()
	// keep part of the BIOS Pad before the new fv if needed
	if bp.Offset < offset {
		hbp, err := uefi.NewBIOSPadding(bpBuf[:offset-bp.Offset], bp.Offset)
		if err != nil {
			return err
		}
		newElements = append(newElements, uefi.MakeTyped(hbp))
	}

	// Add the FV
	newElements = append(newElements, uefi.MakeTyped(fv))

	// keep part of the BIOS Pad after the new fv if needed
	if offset-bp.Offset+fv.Length < uint64(len(bpBuf)) {
		tbp, err := uefi.NewBIOSPadding(bpBuf[offset-bp.Offset+fv.Length:], offset+fv.Length)
		if err != nil {
			return err
		}
		newElements = append(newElements, uefi.MakeTyped(tbp))
	}

	// Keep the remaining Elements in the BIOS Region
	if idx+1 < len(br.Elements) {
		newElements = append(newElements, br.Elements[idx+1:]...)
	}
	br.Elements = newElements
	return nil
}

func createEmptyFirmwareVolume(fvOffset, size uint64, name *guid.GUID) (*uefi.FirmwareVolume, error) {
	// TODO: can this be refactored with the code in repack.go and assemble.go ?
	fv := &uefi.FirmwareVolume{} // new Firmware Volume
	// Set up volume header first.
	fv.FileSystemGUID = *uefi.FFS2
	fv.Signature = binary.LittleEndian.Uint32([]byte("_FVH"))
	// TODO: retrieve all details from (all) other fv in BIOS Region
	fv.Attributes = 0x0004FEFF
	fv.Revision = 2
	// Create Blocks
	fv.Blocks = make([]uefi.Block, 2)
	fv.Blocks[0] = uefi.Block{Size: 4096, Count: uint32(size / 4096)}
	fv.Blocks[1] = uefi.Block{}
	// Calculate the HeaderLen field
	fv.HeaderLen = uint16(uefi.FirmwareVolumeFixedHeaderSize + int(unsafe.Sizeof(uefi.Block{}))*len(fv.Blocks))

	fv.DataOffset = uint64(fv.HeaderLen) // unless we add the extended header
	fv.Length = size

	if name != nil {
		// TODO: should the extended header offset be computed ?
		fv.ExtHeaderOffset = 0x60
		fv.FVName = *name
		fv.ExtHeaderSize = uefi.FirmwareVolumeExtHeaderMinSize
	}
	// Generate binary header.
	header := new(bytes.Buffer)
	err := binary.Write(header, binary.LittleEndian, fv.FirmwareVolumeFixedHeader)
	if err != nil {
		return nil, fmt.Errorf("unable to construct binary header of new firmware volume: got %v", err)
	}
	for _, b := range fv.Blocks {
		err = binary.Write(header, binary.LittleEndian, b)
		if err != nil {
			return nil, fmt.Errorf("unable to construct binary header of new firmware volume: got %v", err)
		}

	}
	buf := header.Bytes()

	// Checksum the header
	sum, err := uefi.Checksum16(buf[:fv.HeaderLen])
	if err != nil {
		return nil, err
	}
	newSum := 0 - sum
	binary.LittleEndian.PutUint16(buf[50:], newSum)

	// Store the header buffer in
	fv.SetBuf(buf)

	if name != nil {
		// Build the ExtHeader
		extHeader := new(bytes.Buffer)
		err = binary.Write(extHeader, binary.LittleEndian, fv.FirmwareVolumeExtHeader)
		if err != nil {
			return nil, fmt.Errorf("unable to construct binary extended header of new firmware volume: got %v", err)
		}

		extHeaderFile, err := uefi.CreatePadFile(uint64(uefi.FileHeaderMinLength + fv.ExtHeaderSize))
		if err != nil {
			return nil, fmt.Errorf("Building ExtHeader %v", err)
		}
		if err := extHeaderFile.ChecksumAndAssemble(extHeader.Bytes()); err != nil {
			return nil, fmt.Errorf("Building ExtHeader %v", err)
		}

		// Add the extended header in a Padfile just after the header.
		extHeaderFileBuf := extHeaderFile.Buf()
		if err = fv.InsertFile(fv.DataOffset, extHeaderFileBuf); err != nil {
			return nil, fmt.Errorf("Adding ExtHeader %v", err)
		}
		fv.DataOffset += uint64(len(extHeaderFileBuf))
	}
	// Add empty space
	extLen := fv.Length - fv.DataOffset
	emptyBuf := make([]byte, extLen)
	uefi.Erase(emptyBuf, uefi.Attributes.ErasePolarity)

	// Store the buffer in
	fv.SetBuf(append(fv.Buf(), emptyBuf...))

	// Make sure DataOffset is 8 byte aligned at least.
	fv.DataOffset = uefi.Align8(fv.DataOffset)

	// Internal fields
	fv.FVOffset = fvOffset
	fv.FreeSpace = fv.Length - fv.DataOffset

	return fv, nil
}

func init() {
	RegisterCLI("create-fv", "creates a FV given an offset, size and volume GUID (can only replace a BIOS Padding)", 3, func(args []string) (uefi.Visitor, error) {
		offset, err := strconv.ParseUint(args[0], 0, 64)
		if err != nil {
			return nil, err
		}
		size, err := strconv.ParseUint(args[1], 0, 64)
		if err != nil {
			return nil, err
		}
		name, err := guid.Parse(args[2])
		if err != nil {
			return nil, err
		}
		return &CreateFV{
			AbsOffset: offset,
			Size:      size,
			Name:      *name,
		}, nil
	})
}
