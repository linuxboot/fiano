package consts

import (
	uefiConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
)

const (
	BasePhysAddr = uefiConsts.BasePhysAddr

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
