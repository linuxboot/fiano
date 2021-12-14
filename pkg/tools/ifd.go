package tools

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/linuxboot/fiano/pkg/fmap"
	"github.com/linuxboot/fiano/pkg/uefi"
	"github.com/linuxboot/fiano/pkg/uefi/consts"
)

func getCorebootRegion(image []byte) (uint32, uint32, error) {
	in := bytes.NewReader(image)
	f, _, err := fmap.Read(in)
	if err != nil {
		return 0, 0, err
	}
	i := f.IndexOfArea("COREBOOT")
	if i < 0 {
		return 0, 0, errors.New("COREBOOT region not found")
	}
	return f.Areas[i].Offset, f.Areas[i].Size, nil
}

// CalcImageOffset returns the offset of a given uefi flash image
func CalcImageOffset(image []byte, addr uint64) (uint64, error) {
	off, size, ifdErr := GetRegion(image, uefi.RegionTypeBIOS)
	if ifdErr == nil {
		return uint64(off+size) - consts.BasePhysAddr + addr, nil
	}
	// If no IFD is present we are not dealing with a full image,
	// but maybe a BIOS region only image. Attempt to parse coreboot fmap.
	var cbErr error
	off, size, cbErr = getCorebootRegion(image)
	// If it's not a proper coreboot image return the IFD error as this is more generic.
	if cbErr != nil {
		return 0, ifdErr
	}
	return uint64(off+size) - consts.BasePhysAddr + addr, nil
}

// GetRegion returns offset and size of the given region type.
func GetRegion(image []byte, regionType uefi.FlashRegionType) (uint32, uint32, error) {
	if _, err := uefi.FindSignature(image); err != nil {
		return 0, 0, err
	}
	flash, err := uefi.NewFlashImage(image)
	if err != nil {
		return 0, 0, err
	}
	if flash.IFD.Region.FlashRegions[regionType].Valid() {
		offset := flash.IFD.Region.FlashRegions[regionType].BaseOffset()
		size := flash.IFD.Region.FlashRegions[regionType].EndOffset() - offset
		return offset, size, nil
	}
	return 0, 0, fmt.Errorf("couldn't find region %d", regionType)
}
