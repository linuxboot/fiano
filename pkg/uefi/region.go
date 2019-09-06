// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"fmt"
)

const (
	// RegionBlockSize assumes the region struct values correspond to blocks of 0x1000 in size
	RegionBlockSize = 0x1000
)

// FlashRegionType represents the different types possible in a flash region.
type FlashRegionType int

// IFD Region types.
// This also corresponds to their index in the flash region section.
// Referenced from github.com/LongSoft/UEFITool, common/descriptor.h.
const (
	RegionTypeBIOS FlashRegionType = iota
	RegionTypeME
	RegionTypeGBE
	RegionTypePD
	RegionTypeDevExp1
	RegionTypeBIOS2
	RegionTypeMicrocode
	RegionTypeEC
	RegionTypeDevExp2
	RegionTypeIE
	RegionTypeTGBE1
	RegionTypeTGBE2
	RegionTypeReserved1
	RegionTypeReserved2
	RegionTypePTT

	RegionTypeUnknown FlashRegionType = -1
)

var flashRegionTypeNames = map[FlashRegionType]string{
	RegionTypeBIOS:      "BIOS",
	RegionTypeME:        "ME",
	RegionTypeGBE:       "GbE",
	RegionTypePD:        "PD",
	RegionTypeDevExp1:   "DevExp1",
	RegionTypeBIOS2:     "BIOS2",
	RegionTypeMicrocode: "Microcode",
	RegionTypeEC:        "EC",
	RegionTypeDevExp2:   "DevExp2",
	RegionTypeIE:        "IE",
	RegionTypeTGBE1:     "10GbE1",
	RegionTypeTGBE2:     "10GbE2",
	RegionTypeReserved1: "Reserved1",
	RegionTypeReserved2: "Reserved2",
	RegionTypePTT:       "PTT",
	// RegionTypeUnknown doesn't have a string name, we want it
	// to fallback and print the number
}

func (rt FlashRegionType) String() string {
	if s, ok := flashRegionTypeNames[rt]; ok {
		return s
	}
	return fmt.Sprintf("Unknown Region (%d)", rt)
}

// FlashRegion holds the base and limit of every type of region. Each region such as the bios region
// should point back to it.
// TODO: figure out of block sizes are read from some location on flash or fixed.
// Right now we assume they're fixed to 4KiB
type FlashRegion struct {
	Base  uint16 // Index of first 4KiB block
	Limit uint16 // Index of last block
}

// Valid checks to see if a region is valid
func (r *FlashRegion) Valid() bool {
	// The ODROID bios seems to be different from all other bioses, and seems to not report
	// invalid regions correctly. They report a limit and base of 0xFFFF instead of a limit of 0
	return r.Limit > 0 && r.Limit >= r.Base && r.Limit != 0xFFFF && r.Base != 0xFFFF
}

func (r *FlashRegion) String() string {
	return fmt.Sprintf("[%#x, %#x)", r.Base, r.Limit)
}

// BaseOffset calculates the offset into the flash image where the Region begins
func (r *FlashRegion) BaseOffset() uint32 {
	return uint32(r.Base) * RegionBlockSize
}

// EndOffset calculates the offset into the flash image where the Region ends
func (r *FlashRegion) EndOffset() uint32 {
	return (uint32(r.Limit) + 1) * RegionBlockSize
}

var regionConstructors = map[FlashRegionType]func(buf []byte, r *FlashRegion, rt FlashRegionType) (Region, error){
	RegionTypeBIOS:      NewBIOSRegion,
	RegionTypeME:        NewMERegion,
	RegionTypeGBE:       NewRawRegion,
	RegionTypePD:        NewRawRegion,
	RegionTypeDevExp1:   NewRawRegion,
	RegionTypeBIOS2:     NewRawRegion,
	RegionTypeMicrocode: NewRawRegion,
	RegionTypeEC:        NewRawRegion,
	RegionTypeDevExp2:   NewRawRegion,
	RegionTypeIE:        NewRawRegion,
	RegionTypeTGBE1:     NewRawRegion,
	RegionTypeTGBE2:     NewRawRegion,
	RegionTypeReserved1: NewRawRegion,
	RegionTypeReserved2: NewRawRegion,
	RegionTypePTT:       NewRawRegion,
	RegionTypeUnknown:   NewRawRegion,
}

// Region contains the start and end of a region in flash. This can be a BIOS, ME, PDR or GBE region.
type Region interface {
	Firmware
	Type() FlashRegionType
	FlashRegion() *FlashRegion
	SetFlashRegion(fr *FlashRegion)
}
