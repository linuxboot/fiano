// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
)

// FlashSignature is the sequence of bytes that a Flash image is expected to
// start with.
var (
	FlashSignature = []byte{0x5a, 0xa5, 0xf0, 0x0f}
)

const (
	// FlashDescriptorLength represents the size of the descriptor region.
	FlashDescriptorLength = 0x1000
	// FlashSignatureLength represents the size of the flash signature
	FlashSignatureLength = 4
)

// FlashDescriptor is the main structure that represents an Intel Flash Descriptor.
type FlashDescriptor struct {
	// Holds the raw buffer
	buf                []byte
	DescriptorMapStart uint
	RegionStart        uint
	MasterStart        uint
	DescriptorMap      *FlashDescriptorMap
	Region             *FlashRegionSection
	Master             *FlashMasterSection

	//Metadata for extraction and recovery
	ExtractPath string
}

// FindSignature searches for an Intel flash signature.
func FindSignature(buf []byte) (int, error) {
	if bytes.Equal(buf[16:16+FlashSignatureLength], FlashSignature) {
		// 16 + 4 since the descriptor starts after the signature
		return 20, nil
	}
	if bytes.Equal(buf[:FlashSignatureLength], FlashSignature) {
		// + 4 since the descriptor starts after the signature
		return FlashSignatureLength, nil
	}
	return -1, fmt.Errorf("Flash signature not found: first 20 bytes are:\n%s",
		hex.Dump(buf[:20]))
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (fd *FlashDescriptor) Buf() []byte {
	return fd.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (fd *FlashDescriptor) SetBuf(buf []byte) {
	fd.buf = buf
}

// Apply calls the visitor on the FlashDescriptor.
func (fd *FlashDescriptor) Apply(v Visitor) error {
	return v.Visit(fd)
}

// ApplyChildren calls the visitor on each child node of FlashDescriptor.
func (fd *FlashDescriptor) ApplyChildren(v Visitor) error {
	return nil
}

// ParseFlashDescriptor parses the ifd from the buffer
func (fd *FlashDescriptor) ParseFlashDescriptor() error {
	if buflen := len(fd.buf); buflen != FlashDescriptorLength {
		return fmt.Errorf("flash descriptor length not %#x, was %#x", FlashDescriptorLength, buflen)
	}

	descriptorMapStart, err := FindSignature(fd.buf)
	if err != nil {
		return err
	}
	fd.DescriptorMapStart = uint(descriptorMapStart)

	// Descriptor Map
	desc, err := NewFlashDescriptorMap(fd.buf[fd.DescriptorMapStart : fd.DescriptorMapStart+FlashDescriptorMapSize])
	if err != nil {
		return err
	}
	fd.DescriptorMap = desc

	// Region
	fd.RegionStart = uint(fd.DescriptorMap.RegionBase) * 0x10
	region, err := NewFlashRegionSection(fd.buf[fd.RegionStart : fd.RegionStart+uint(FlashRegionSectionSize)])
	if err != nil {
		return err
	}
	fd.Region = region

	// Master
	fd.MasterStart = uint(fd.DescriptorMap.MasterBase) * 0x10
	master, err := NewFlashMasterSection(fd.buf[fd.MasterStart : fd.MasterStart+uint(FlashMasterSectionSize)])
	if err != nil {
		return err
	}
	fd.Master = master

	return nil
}

// FlashImage is the main structure that represents an Intel Flash image. It
// implements the Firmware interface.
type FlashImage struct {
	// Holds the raw buffer
	buf []byte
	// Holds the Flash Descriptor
	IFD FlashDescriptor
	// Actual regions
	Regions []Region `json:",omitempty"`

	// Metadata for extraction and recovery
	ExtractPath string
	FlashSize   uint64
}

// Buf returns the buffer.
// Used mostly for things interacting with the Firmware interface.
func (f *FlashImage) Buf() []byte {
	return f.buf
}

// SetBuf sets the buffer.
// Used mostly for things interacting with the Firmware interface.
func (f *FlashImage) SetBuf(buf []byte) {
	f.buf = buf
}

// Apply calls the visitor on the FlashImage.
func (f *FlashImage) Apply(v Visitor) error {
	return v.Visit(f)
}

// ApplyChildren calls the visitor on each child node of FlashImage.
func (f *FlashImage) ApplyChildren(v Visitor) error {
	if err := f.IFD.Apply(v); err != nil {
		return err
	}
	for _, r := range f.Regions {
		if err := r.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

// IsPCH returns whether the flash image has the more recent PCH format, or not.
// PCH images have the first 16 bytes reserved, and the 4-bytes signature starts
// immediately after. Older images (ICH8/9/10) have the signature at the
// beginning.
// TODO: Check this. What if we have the signature in both places? I feel like the check
// should be IsICH because I expect the ICH to override PCH if the signature exists in 0:4
// since in that case 16:20 should be data. If that's the case, FindSignature needs to
// be fixed as well
func (f *FlashImage) IsPCH() bool {
	return bytes.Equal(f.buf[16:16+len(FlashSignature)], FlashSignature)
}

// FindSignature looks for the Intel flash signature, and returns its offset
// from the start of the image. The PCH images are located at offset 16, while
// in ICH8/9/10 they start at 0. If no signature is found, it returns -1.
func (f *FlashImage) FindSignature() (int, error) {
	return FindSignature(f.buf)
}

func (f *FlashImage) String() string {
	return fmt.Sprintf("FlashImage{Size=%v, Descriptor=%v, Region=%v, Master=%v}",
		len(f.buf),
		f.IFD.DescriptorMap.String(),
		f.IFD.Region.String(),
		f.IFD.Master.String(),
	)
}

func (f *FlashImage) fillRegionGaps() error {
	// Search for gaps and fill in with unknown regions
	offset := uint64(FlashDescriptorLength)
	var newRegions []Region
	for _, r := range f.Regions {
		nextBase := uint64(r.FlashRegion().BaseOffset())
		if nextBase < offset {
			// Something is wrong, overlapping regions
			// TODO: print a better error message describing what it overlaps with
			return fmt.Errorf("overlapping regions! region type %s overlaps with the previous region",
				r.Type().String())
		}
		if nextBase > offset {
			// There is a gap, create an unknown region
			tempFR := &FlashRegion{Base: uint16(offset / RegionBlockSize),
				Limit: uint16(nextBase/RegionBlockSize) - 1}
			newRegions = append(newRegions, &RawRegion{buf: f.buf[offset:nextBase],
				flashRegion: tempFR,
				RegionType:  RegionTypeUnknown})
		}
		offset = uint64(r.FlashRegion().EndOffset())
		newRegions = append(newRegions, r)
	}
	// check for the last region
	if offset != f.FlashSize {
		tempFR := &FlashRegion{Base: uint16(offset / RegionBlockSize),
			Limit: uint16(f.FlashSize/RegionBlockSize) - 1}
		newRegions = append(newRegions, &RawRegion{buf: f.buf[offset:f.FlashSize],
			flashRegion: tempFR,
			RegionType:  RegionTypeUnknown})
	}
	f.Regions = newRegions
	return nil
}

// NewFlashImage tries to create a FlashImage structure, and returns a FlashImage
// and an error if any. This only works with images that operate in Descriptor
// mode.
func NewFlashImage(buf []byte) (*FlashImage, error) {
	if len(buf) < FlashDescriptorMapSize {
		return nil, fmt.Errorf("Flash Descriptor Map size too small: expected %v bytes, got %v",
			FlashDescriptorMapSize,
			len(buf),
		)
	}
	f := FlashImage{buf: buf, FlashSize: uint64(len(buf))}
	f.IFD.buf = buf[:FlashDescriptorLength]
	if err := f.IFD.ParseFlashDescriptor(); err != nil {
		return nil, err
	}

	// FlashRegions
	frs := f.IFD.Region.FlashRegions

	// BIOS region has to be valid
	if !frs[RegionTypeBIOS].Valid() {
		return nil, fmt.Errorf("no BIOS region: invalid region parameters %v", frs[RegionTypeBIOS])
	}

	nr := int(f.IFD.DescriptorMap.NumberOfRegions)
	// Parse all the regions
	for i, fr := range frs {
		// Parse only a smaller number of regions if number of regions isn't 0
		// Number of regions is deprecated in newer IFDs and is just 0, older IFDs report
		// the number of regions and have falsely "valid" regions after that number.
		if nr != 0 && i >= nr {
			break
		}
		if !fr.Valid() {
			continue
		}
		if o := uint64(fr.BaseOffset()); o >= f.FlashSize {
			fmt.Printf("region %s (%d, %v) out of bounds: BaseOffset %#x, Flash size %#x, skipping...\n",
				flashRegionTypeNames[FlashRegionType(i)], i, fr, o, f.FlashSize)
			continue
		}
		if o := uint64(fr.EndOffset()); o > f.FlashSize {
			fmt.Printf("region %s (%d, %v) out of bounds: EndOffset %#x, Flash size %#x, skipping...\n",
				flashRegionTypeNames[FlashRegionType(i)], i, fr, o, f.FlashSize)
			continue
		}
		if c, ok := regionConstructors[FlashRegionType(i)]; ok {
			r, err := c(buf[fr.BaseOffset():fr.EndOffset()], &frs[i], FlashRegionType(i))
			if err != nil {
				return nil, err
			}
			f.Regions = append(f.Regions, r)
		}
	}

	// Sort the regions by offset so we can look for gaps
	sort.Slice(f.Regions, func(i, j int) bool {
		return f.Regions[i].FlashRegion().Base < f.Regions[j].FlashRegion().Base
	})

	if err := f.fillRegionGaps(); err != nil {
		return nil, err
	}
	return &f, nil
}
