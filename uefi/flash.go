package uefi

import (
	"bytes"
	"fmt"
)

// FlashSignature is the sequence of bytes that a Flash image is expected to
// start with.
var (
	FlashSignature = []byte{0x5a, 0xa5, 0xf0, 0x0f}
)

const (
	// FlashDescriptorLength represents the size of the IFD.
	FlashDescriptorLength = 0x1000
)

// FlashDescriptor is the main structure that represents an Intel Flash Descriptor.
type FlashDescriptor struct {
	// Holds the raw buffer
	buf                []byte
	DescriptorMapStart uint
	RegionStart        uint
	MasterStart        uint
	DescriptorMap      FlashDescriptorMap
	Region             FlashRegionSection
	Master             FlashMasterSection

	//Metadata for extraction and recovery
	ExtractPath string
}

// FlashImage is the main structure that represents an Intel Flash image. It
// implements the Firmware interface.
type FlashImage struct {
	// Holds the raw buffer
	buf []byte
	// Holds the Flash Descriptor
	IFD FlashDescriptor
	// Actual regions
	BIOSRegion *BIOSRegion

	// Metadata for extraction and recovery
	ExtractPath string
}

// IsPCH returns whether the flash image has the more recent PCH format, or not.
// PCH images have the first 16 bytes reserved, and the 4-bytes signature starts
// immediately after. Older images (ICH8/9/10) have the signature at the
// beginning.
func (f FlashImage) IsPCH() bool {
	return bytes.Equal(f.buf[16:16+len(FlashSignature)], FlashSignature)
}

// FindSignature looks for the Intel flash signature, and returns its offset
// from the start of the image. The PCH images are located at offset 16, while
// in ICH8/9/10 they start at 0. If no signature is found, it returns -1.
func (f FlashImage) FindSignature() (int, error) {
	if bytes.Equal(f.buf[16:16+len(FlashSignature)], FlashSignature) {
		// 16 + 4 since the descriptor starts after the signature
		return 20, nil
	}
	if bytes.Equal(f.buf[:len(FlashSignature)], FlashSignature) {
		// + 4 since the descriptor starts after the signature
		return 4, nil
	}
	return -1, fmt.Errorf("Flash signature not found")
}

// Validate runs a set of checks on the flash image and returns a list of
// errors specifying what is wrong.
func (f FlashImage) Validate() []error {
	errors := make([]error, 0)
	_, err := f.FindSignature()
	if err != nil {
		errors = append(errors, err)
	}
	errors = append(errors, f.IFD.DescriptorMap.Validate()...)
	// TODO also validate regions, masters, etc
	return errors
}

func (f FlashImage) String() string {
	return fmt.Sprintf("FlashImage{Size=%v, Descriptor=%v, Region=%v, Master=%v}",
		len(f.buf),
		f.IFD.DescriptorMap.String(),
		f.IFD.Region.String(),
		f.IFD.Master.String(),
	)
}

// Summary prints a multi-line description of the flash image
func (f FlashImage) Summary() string {
	return fmt.Sprintf("FlashImage{\n"+
		"    Size=%v\n"+
		"    DescriptorMapStart=%v\n"+
		"    RegionStart=%v\n"+
		"    MasterStart=%v\n"+
		"    Descriptor=%v\n"+
		"    Region=%v\n"+
		"    Master=%v\n"+
		"    BIOSRegion=%v\n"+
		"}",
		len(f.buf),
		f.IFD.DescriptorMapStart,
		f.IFD.RegionStart,
		f.IFD.MasterStart,
		Indent(f.IFD.DescriptorMap.Summary(), 4),
		Indent(f.IFD.Region.Summary(), 4),
		Indent(f.IFD.Master.Summary(), 4),
		Indent(f.BIOSRegion.Summary(), 4),
	)
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
	f := FlashImage{buf: buf}
	f.IFD.buf = f.buf[:FlashDescriptorLength]
	descriptorMapStart, err := f.FindSignature()
	if err != nil {
		return nil, err
	}
	f.IFD.DescriptorMapStart = uint(descriptorMapStart)

	// Descriptor Map
	desc, err := NewFlashDescriptorMap(buf[f.IFD.DescriptorMapStart : f.IFD.DescriptorMapStart+FlashDescriptorMapSize])
	if err != nil {
		return nil, err
	}
	f.IFD.DescriptorMap = *desc

	// Region
	f.IFD.RegionStart = uint(f.IFD.DescriptorMap.RegionBase) * 0x10
	region, err := NewFlashRegionSection(buf[f.IFD.RegionStart : f.IFD.RegionStart+uint(FlashRegionSectionSize)])
	if err != nil {
		return nil, err
	}
	f.IFD.Region = *region

	// Master
	f.IFD.MasterStart = uint(f.IFD.DescriptorMap.MasterBase) * 0x10
	master, err := NewFlashMasterSection(buf[f.IFD.MasterStart : f.IFD.MasterStart+uint(FlashMasterSectionSize)])
	if err != nil {
		return nil, err
	}
	f.IFD.Master = *master

	// BIOS region
	br, err := NewBIOSRegion(buf[f.IFD.Region.BIOS.BaseOffset():f.IFD.Region.BIOS.EndOffset()], &f.IFD.Region.BIOS)
	if err != nil {
		return nil, err
	}
	f.BIOSRegion = br

	return &f, nil
}
