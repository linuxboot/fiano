// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"fmt"
	"log"

	"github.com/linuxboot/fiano/pkg/uefi"
)

// TightenME tighten ME's belt to give more room for LinuxBoot
// This changes the ME Region Limit to fit the actual content as described in the ME partitions. Also update the BIOS Region Base to start just after the ME Region
type TightenME struct {
	fd  *uefi.FlashDescriptor
	mer *uefi.MERegion
	br  *uefi.BIOSRegion
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *TightenME) Run(f uefi.Firmware) error {
	err := f.Apply(v)
	if err != nil {
		return fmt.Errorf("error looking for IFD, ME and BIOS regions: %v", err)
	}

	return v.process()
}

// Visit applies the TightenME visitor to any Firmware type.
func (v *TightenME) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FlashDescriptor:
		v.fd = f
		return nil
	case *uefi.MERegion:
		v.mer = f
		return nil
	case *uefi.BIOSRegion:
		v.br = f
		return nil
	default:
		return f.ApplyChildren(v)
	}
}

func (v *TightenME) process() error {
	// Ensuring IFD exists also ensure FRegion are populated in Regions
	if v.fd == nil {
		return fmt.Errorf("no IFD found")
	}
	if v.mer == nil {
		return fmt.Errorf("no ME region found")
	}
	if v.br == nil {
		return fmt.Errorf("no BIOS region found")
	}
	// TODO: We might be able to relax this restriction if there is a region
	// in between that can be shifted, but this needs more tests...
	if v.mer.FRegion.EndOffset() != v.br.FRegion.BaseOffset() {
		return fmt.Errorf("ME and BIOS regions are not contiguous: ME end at %#x BIOS starts at %#x", v.mer.FRegion.EndOffset(), v.br.FRegion.BaseOffset())

	}
	// Compute the new limit
	updateOffset := uint64(v.mer.FRegion.BaseOffset()) + v.mer.FreeSpaceOffset
	updateBase := (updateOffset + uefi.RegionBlockSize - 1) / uefi.RegionBlockSize
	// align the new absolute offset to uefi.RegionBlockSize
	updateOffset = updateBase * uefi.RegionBlockSize
	bufOffset := updateOffset - uint64(v.mer.FRegion.BaseOffset())
	// check the zone if empty
	buf := v.mer.Buf()
	if !uefi.IsErased(buf[bufOffset:], uefi.Attributes.ErasePolarity) {
		return fmt.Errorf("ME unused space in not erased as expected")
	}
	// Shrink ME Region
	v.mer.FRegion.Limit = uint16(updateBase - 1)
	v.mer.SetBuf(buf[:bufOffset])
	// Expand BIOS Region
	offsetShift := uint64(v.br.FRegion.BaseOffset()) - updateOffset
	v.br.FRegion.Base = uint16(updateBase)
	v.br.Length += offsetShift
	if v.br.Length > 16*1024*1024 {
		log.Printf("warning new BIOS Regions length %d (%#x) exceed 16MiB limit", v.br.Length, v.br.Length)
	}
	// update elements offsets
	for i, e := range v.br.Elements {
		switch f := e.Value.(type) {
		case *uefi.FirmwareVolume:
			f.FVOffset += offsetShift
		case *uefi.BIOSPadding:
			f.Offset += offsetShift
		default:
			return fmt.Errorf("Unexpected Element at %d: %s", i, e.Type)
		}
	}
	// insert BIOSPad
	bp, err := uefi.NewBIOSPadding(buf[bufOffset:], 0)
	if err != nil {
		return fmt.Errorf("Could not create BIOS Padding: %v", err)
	}
	v.br.Elements = append([]*uefi.TypedFirmware{uefi.MakeTyped(bp)}, v.br.Elements...)
	// Update IFD
	// I thought regions had references to the IFD... but it seams not so:
	v.fd.Region.FlashRegions[uefi.RegionTypeBIOS] = *v.br.FRegion
	v.fd.Region.FlashRegions[uefi.RegionTypeME] = *v.mer.FRegion
	// Assemble will regenerate IFD so regions will be updated in the image

	return nil
}

func init() {
	RegisterCLI("tighten_me", "tighten ME's belt to give more room for LinuxBoot", 0, func(args []string) (uefi.Visitor, error) {
		return &TightenME{}, nil
	})
}
