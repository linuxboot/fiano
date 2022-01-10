// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import "github.com/linuxboot/fiano/pkg/intel/metadata/fit/consts"

// CalculatePhysAddrFromOffset calculates the physical address (address to a
// region mapped from the SPI chip) using an offset withtin an image, relatively
// to BasePhysAddr.
//
// Examples:
//     CalculatePhysAddrFromOffset(0x01, 0x2000) ==  0xffffe001
//     CalculatePhysAddrFromOffset(0x40, 0x2000) ==  0xffffe040
func CalculatePhysAddrFromOffset(offset uint64, imageSize uint64) uint64 {
	startAddr := consts.BasePhysAddr - imageSize
	return startAddr + offset
}

// CalculateOffsetFromPhysAddr calculates the offset within an image
// of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//     CalculateOffsetFromPhysAddr(0xffffffff, 0x1000) == 0xfff
//     CalculateOffsetFromPhysAddr(0xffffffc0, 0x1000) == 0xfc0
func CalculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	startAddr := consts.BasePhysAddr - imageSize
	return physAddr - startAddr
}

// CalculateTailOffsetFromPhysAddr calculates the offset (towards down, relatively
// to BasePhysAddr) of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//     CalculateTailOffsetFromPhysAddr(0xffffffff) == 0x01
//     CalculateTailOffsetFromPhysAddr(0xffffffc0) == 0x40
func CalculateTailOffsetFromPhysAddr(physAddr uint64) uint64 {
	return consts.BasePhysAddr - physAddr
}
