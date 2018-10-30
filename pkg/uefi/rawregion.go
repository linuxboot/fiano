// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

// RawRegion implements Region for a raw chunk of bytes in the firmware image.
type RawRegion struct {
	// holds the raw data
	buf []byte
	// Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the FlashRegion struct laid out in the ifd.
	flashRegion *FlashRegion
	// Region Type as per the IFD
	RegionType FlashRegionType
}

// SetFlashRegion sets the flash region.
func (rr *RawRegion) SetFlashRegion(fr *FlashRegion) {
	rr.flashRegion = fr
}

// FlashRegion gets the flash region.
func (rr *RawRegion) FlashRegion() (fr *FlashRegion) {
	return rr.flashRegion
}

// NewRawRegion creates a new region.
func NewRawRegion(buf []byte, r *FlashRegion, rt FlashRegionType) (Region, error) {
	rr := &RawRegion{flashRegion: r, RegionType: rt}
	rr.buf = make([]byte, len(buf))
	copy(rr.buf, buf)
	return rr, nil
}

// Type returns the flash region type.
func (rr *RawRegion) Type() FlashRegionType {
	return rr.RegionType
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (rr *RawRegion) Buf() []byte {
	return rr.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (rr *RawRegion) SetBuf(buf []byte) {
	rr.buf = buf
}

// Apply calls the visitor on the RawRegion.
func (rr *RawRegion) Apply(v Visitor) error {
	return v.Visit(rr)
}

// ApplyChildren calls the visitor on each child node of RawRegion.
func (rr *RawRegion) ApplyChildren(v Visitor) error {
	return nil
}
