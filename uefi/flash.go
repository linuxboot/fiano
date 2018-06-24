package uefi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
)

// FlashSignature is the sequence of bytes that a Flash image is expected to
// start with.
var (
	FlashSignature = []byte{0x5a, 0xa5, 0xf0, 0x0f}
)

const (
	// FlashDescriptorLength represents the size of the descriptor region.
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

// Validate the descriptor region
func (fd *FlashDescriptor) Validate() []error {
	// TODO: Validate the other sections too.
	return fd.DescriptorMap.Validate()
}

// Extract extracts the flash descriptor region to the directory passed in.
func (fd *FlashDescriptor) Extract(parentPath string) error {
	var err error
	dirPath := filepath.Join(parentPath, "ifd")
	// We just dump the binary for now
	fd.ExtractPath, err = ExtractBinary(fd.buf, dirPath, "flashdescriptor.bin")
	return err
}

// FlashImage is the main structure that represents an Intel Flash image. It
// implements the Firmware interface.
type FlashImage struct {
	// Holds the raw buffer
	buf []byte
	// Holds the Flash Descriptor
	IFD FlashDescriptor
	// Actual regions
	BIOS *BIOSRegion
	ME   *MERegion
	GBE  *GBERegion
	PD   *PDRegion

	// Metadata for extraction and recovery
	ExtractPath string
	regions     []Firmware
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
	if bytes.Equal(f.buf[16:16+len(FlashSignature)], FlashSignature) {
		// 16 + 4 since the descriptor starts after the signature
		return 20, nil
	}
	if bytes.Equal(f.buf[:len(FlashSignature)], FlashSignature) {
		// + 4 since the descriptor starts after the signature
		return 4, nil
	}
	return -1, fmt.Errorf("Flash signature not found: first 20 bytes are:\n%s",
		hex.Dump(f.buf[:20]))
}

// Validate runs a set of checks on the flash image and returns a list of
// errors specifying what is wrong.
func (f *FlashImage) Validate() []error {
	errors := make([]error, 0)
	_, err := f.FindSignature()
	if err != nil {
		errors = append(errors, err)
	}
	errors = append(errors, f.IFD.DescriptorMap.Validate()...)
	// TODO also validate regions, masters, etc
	errors = append(errors, f.BIOS.Validate()...)
	return errors
}

// Extract extracts the flash image to the directory passed in.
func (f *FlashImage) Extract(dirPath string) error {
	absDirPath, err := filepath.Abs(dirPath)
	if err != nil {
		return err
	}
	// Dump the binary
	f.ExtractPath, err = ExtractBinary(f.buf, absDirPath, "flash.rom")
	if err != nil {
		return err
	}

	// Extract all regions.
	for _, r := range f.regions {
		if err = r.Extract(absDirPath); err != nil {
			return err
		}
	}

	// Output summary json. This must be done after all other extract calls so that
	// any metadata fields in sub structures are generated properly.
	jsonPath := filepath.Join(absDirPath, "summary.json")
	b, err := json.MarshalIndent(f, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(jsonPath, b, 0666)
}

func (f *FlashImage) String() string {
	return fmt.Sprintf("FlashImage{Size=%v, Descriptor=%v, Region=%v, Master=%v}",
		len(f.buf),
		f.IFD.DescriptorMap.String(),
		f.IFD.Region.String(),
		f.IFD.Master.String(),
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

	// Add to extractable regions
	f.regions = append(f.regions, &f.IFD)

	// BIOS region
	if !f.IFD.Region.BIOS.Valid() {
		return nil, fmt.Errorf("no BIOS region: invalid region parameters %v", f.IFD.Region.BIOS)
	}
	br, err := NewBIOSRegion(buf[f.IFD.Region.BIOS.BaseOffset():f.IFD.Region.BIOS.EndOffset()], &f.IFD.Region.BIOS)
	if err != nil {
		return nil, err
	}
	f.BIOS = br
	// Add to extractable regions
	f.regions = append(f.regions, f.BIOS)

	// ME region
	if f.IFD.Region.ME.Valid() {
		mer, err := NewMERegion(buf[f.IFD.Region.ME.BaseOffset():f.IFD.Region.ME.EndOffset()], &f.IFD.Region.ME)
		if err != nil {
			return nil, err
		}
		f.ME = mer
		// Add to extractable regions
		f.regions = append(f.regions, f.ME)
	}

	// GBE region
	if f.IFD.Region.GBE.Valid() {
		gber, err := NewGBERegion(buf[f.IFD.Region.GBE.BaseOffset():f.IFD.Region.GBE.EndOffset()], &f.IFD.Region.GBE)
		if err != nil {
			return nil, err
		}
		f.GBE = gber
		// Add to extractable regions
		f.regions = append(f.regions, f.GBE)
	}

	// PD region
	if f.IFD.Region.PD.Valid() {
		pdr, err := NewPDRegion(buf[f.IFD.Region.PD.BaseOffset():f.IFD.Region.PD.EndOffset()], &f.IFD.Region.PD)
		if err != nil {
			return nil, err
		}
		f.PD = pdr
		// Add to extractable regions
		f.regions = append(f.regions, f.PD)
	}

	return &f, nil
}
