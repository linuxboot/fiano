// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import "github.com/linuxboot/fiano/pkg/intel/metadata/fit/consts"

// calculatePhysAddrFromOffset calculates the physical address (address to a
// region mapped from the SPI chip) using an offset withtin an image, relatively
// to BasePhysAddr.
//
// Examples:
//     calculatePhysAddrFromOffset(0x01, 0x2000) ==  0xffffe001
//     calculatePhysAddrFromOffset(0x40, 0x2000) ==  0xffffe040
func calculatePhysAddrFromOffset(offset uint64, imageSize uint64) uint64 {
	startAddr := consts.BasePhysAddr - imageSize
	return startAddr + offset
}

// calculateOffsetFromPhysAddr calculates the offset within an image
// of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//     calculateOffsetFromPhysAddr(0xffffffff, 0x1000) == 0xfff
//     calculateOffsetFromPhysAddr(0xffffffc0, 0x1000) == 0xfc0
func calculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	startAddr := consts.BasePhysAddr - imageSize
	return physAddr - startAddr
}

// calculateTailOffsetFromPhysAddr calculates the offset (towards down, relatively
// to BasePhysAddr) of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//     calculateTailOffsetFromPhysAddr(0xffffffff) == 0x01
//     calculateTailOffsetFromPhysAddr(0xffffffc0) == 0x40
func calculateTailOffsetFromPhysAddr(physAddr uint64) uint64 {
	return consts.BasePhysAddr - physAddr
}
