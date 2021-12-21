// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package consts

const (
	// BasePhysAddr is the absolute physical address where the firmware image ends.
	//
	// See Figure 2.1 in https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	//
	// Note: A firmware image grows towards lower addresses. So an image will be mapped to addresses:
	//       [ BasePhysAddr-length .. BasePhysAddr )
	//
	// Note: SPI chip is mapped into this region. So we actually work directly with data of the SPI chip
	//
	// See also CalculatePhysAddrOfOffset().
	BasePhysAddr = 1 << 32 // "4GB"

	// FITPointerOffset is the offset of the physical address of the FIT pointer.
	// See "1 Firmware Interface Table" in "Firmware Interface Table" specification:
	//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	FITPointerOffset = 0x40

	// FITPointerPhysAddr is the physical address of the FIT pointer.
	// See "1 Firmware Interface Table" in "Firmware Interface Table" specification:
	//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	FITPointerPhysAddr = BasePhysAddr - FITPointerOffset

	// FITPointerSize is the size of the FIT pointer.
	// It is suggested to be 0x10 bytes because of "Figure 1-1" of the specification.
	FITPointerSize = 0x10
)
