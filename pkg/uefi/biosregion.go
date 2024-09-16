// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"errors"
)

// BIOSPadding holds the padding in between firmware volumes
// This may sometimes hold data, even though it shouldn't. We need
// to preserve it though.
type BIOSPadding struct {
	buf    []byte
	Offset uint64

	// Metadata
	ExtractPath string
}

// NewBIOSPadding parses a sequence of bytes and returns a BIOSPadding
// object.
func NewBIOSPadding(buf []byte, offset uint64) (*BIOSPadding, error) {
	bp := &BIOSPadding{buf: buf, Offset: offset}
	return bp, nil
}

// Buf returns the buffer
func (bp *BIOSPadding) Buf() []byte {
	return bp.buf
}

// SetBuf sets the buffer
func (bp *BIOSPadding) SetBuf(buf []byte) {
	bp.buf = buf
}

// Apply a visitor to the BIOSPadding.
func (bp *BIOSPadding) Apply(v Visitor) error {
	return v.Visit(bp)
}

// ApplyChildren applies a visitor to all the direct children of the BIOSPadding
func (bp *BIOSPadding) ApplyChildren(v Visitor) error {
	return nil
}

// BIOSRegion represents the Bios Region in the firmware.
// It holds all the FVs as well as padding
type BIOSRegion struct {
	// holds the raw data
	buf      []byte
	Elements []*TypedFirmware `json:",omitempty"`

	// Metadata for extraction and recovery
	ExtractPath string
	Length      uint64
	// This is a pointer to the FlashRegion struct laid out in the ifd.
	FRegion    *FlashRegion
	RegionType FlashRegionType
}

// Type returns the flash region type.
func (br *BIOSRegion) Type() FlashRegionType {
	return RegionTypeBIOS
}

// SetFlashRegion sets the Flash Region.
func (br *BIOSRegion) SetFlashRegion(fr *FlashRegion) {
	br.FRegion = fr
}

// FlashRegion gets the Flash Region.
func (br *BIOSRegion) FlashRegion() (fr *FlashRegion) {
	return br.FRegion
}

// NewBIOSRegion parses a sequence of bytes and returns a Region
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewBIOSRegion(buf []byte, r *FlashRegion, _ FlashRegionType) (Region, error) {
	br := BIOSRegion{FRegion: r, Length: uint64(len(buf)),
		RegionType: RegionTypeBIOS}
	var absOffset uint64

	// Copy the buffer
	if ReadOnly {
		br.buf = buf
	} else {
		br.buf = make([]byte, len(buf))
		copy(br.buf, buf)
	}

	for {
		offset := FindFirmwareVolumeOffset(buf)
		if offset < 0 {
			// no firmware volume found, stop searching
			// There shouldn't be padding near the end, but store it in case anyway
			if len(buf) != 0 {
				bp, err := NewBIOSPadding(buf, absOffset)
				if err != nil {
					return nil, err
				}
				br.Elements = append(br.Elements, MakeTyped(bp))
			}
			break
		}
		if offset > 0 {
			// There is some padding here, store it in case there is data.
			// We could check and conditionally store, but that makes things more complicated
			bp, err := NewBIOSPadding(buf[:offset], absOffset)
			if err != nil {
				return nil, err
			}
			br.Elements = append(br.Elements, MakeTyped(bp))
		}
		absOffset += uint64(offset)                                  // Find start of volume relative to bios region.
		fv, err := NewFirmwareVolume(buf[offset:], absOffset, false) // False as top level FVs are not resizable
		if err != nil {
			return nil, err
		}
		if fv.Length == 0 {
			//avoid infinite loop
			return nil, errors.New("FV len 0; cannot progress")
		}
		absOffset += fv.Length
		buf = buf[uint64(offset)+fv.Length:]
		br.Elements = append(br.Elements, MakeTyped(fv))
	}
	return &br, nil
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (br *BIOSRegion) Buf() []byte {
	return br.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (br *BIOSRegion) SetBuf(buf []byte) {
	br.buf = buf
}

// Apply calls the visitor on the BIOSRegion.
func (br *BIOSRegion) Apply(v Visitor) error {
	return v.Visit(br)
}

// ApplyChildren calls the visitor on each child node of BIOSRegion.
func (br *BIOSRegion) ApplyChildren(v Visitor) error {
	for _, f := range br.Elements {
		if err := f.Value.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

// FirstFV finds the first firmware volume in the BIOSRegion.
func (br *BIOSRegion) FirstFV() (*FirmwareVolume, error) {
	for _, e := range br.Elements {
		if f, ok := e.Value.(*FirmwareVolume); ok {
			return f, nil
		}
	}
	return nil, errors.New("no firmware volumes in BIOS Region")
}
