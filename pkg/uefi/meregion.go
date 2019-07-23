// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

// MERegion implements Region for a raw chunk of bytes in the firmware image.
type MERegion struct {
	// holds the raw data
	buf []byte
	// Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the FlashRegion struct laid out in the ifd.
	FRegion *FlashRegion
	// Region Type as per the IFD
	RegionType FlashRegionType
}

// SetFlashRegion sets the flash region.
func (rr *MERegion) SetFlashRegion(fr *FlashRegion) {
	rr.FRegion = fr
}

// FlashRegion gets the flash region.
func (rr *MERegion) FlashRegion() (fr *FlashRegion) {
	return rr.FRegion
}

// NewMERegion creates a new region.
func NewMERegion(buf []byte, r *FlashRegion, rt FlashRegionType) (Region, error) {
	rr := &MERegion{FRegion: r, RegionType: rt}
	rr.buf = make([]byte, len(buf))
	copy(rr.buf, buf)
	return rr, nil
}

// Type returns the flash region type.
func (rr *MERegion) Type() FlashRegionType {
	return RegionTypeME
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (rr *MERegion) Buf() []byte {
	return rr.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (rr *MERegion) SetBuf(buf []byte) {
	rr.buf = buf
}

// Apply calls the visitor on the MERegion.
func (rr *MERegion) Apply(v Visitor) error {
	return v.Visit(rr)
}

// ApplyChildren calls the visitor on each child node of MERegion.
func (rr *MERegion) ApplyChildren(v Visitor) error {
	return nil
}
