// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

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
	// See Section 3.1 in "Firmware Interface Table" specification:
	//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	FITPointerOffset = 0x40

	// FITPointerPhysAddr is the physical address of the FIT pointer.
	// See "1 Firmware Interface Table" in "Firmware Interface Table" specification:
	//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	FITPointerPhysAddr = BasePhysAddr - FITPointerOffset

	// FITPointerSize is the size of the FIT pointer.
	// It is suggested to be 0x10 bytes because of "Figure 2-1" of the specification.
	FITPointerSize = 0x10

	// FITHeadersMagic is the magic string, expected in the beginning of the
	// first FIT entry
	FITHeadersMagic = "_FIT_   "

	Version10 BootGuardVersion = 1
	Version20 BootGuardVersion = 2
	Version21 BootGuardVersion = 3

	// Supported algorithms, note that these are supported by both BG and CBnT, though
	// BG uses onlt few of them
	AlgUnknown Algorithm = 0x0000
	AlgRSA     Algorithm = 0x0001
	AlgSHA1    Algorithm = 0x0004
	AlgSHA256  Algorithm = 0x000B
	AlgSHA384  Algorithm = 0x000C
	AlgSHA512  Algorithm = 0x000D
	AlgNull    Algorithm = 0x0010
	AlgSM3     Algorithm = 0x0012
	AlgRSASSA  Algorithm = 0x0014
	AlgRSAPSS  Algorithm = 0x0016
	AlgECDSA   Algorithm = 0x0018
	AlgSM2     Algorithm = 0x001b
	AlgECC     Algorithm = 0x0023

	// Possible values of TPM2PCRExtendPolicySupport
	TPM2PCRExtendIllegal                  TPM2PCRExtendPolicySupport = 0
	TPM2PCRExtendMaximumAgilityPolicy     TPM2PCRExtendPolicySupport = 1
	TPM2PCRExtendMaximumPerformancePolicy TPM2PCRExtendPolicySupport = 2
	TPM2PCRExtendBothPolicies             TPM2PCRExtendPolicySupport = 3

	// Possible types of Manifest fields. Refer to pkg/intel/metadata/README.md
	// for detailed desription of the meaning and usage of these.
	ManifestFieldEndValue               ManifestFieldType = "endValue"
	ManifestFieldArrayStatic            ManifestFieldType = "arrayStatic"
	ManifestFieldArrayDynamicWithSize   ManifestFieldType = "arrayDynamicWithSize"
	ManifestFieldArrayDynamicWithPrefix ManifestFieldType = "arrayDynamicWithPrefix"
	ManifestFieldList                   ManifestFieldType = "list"
	ManifestFieldSubStruct              ManifestFieldType = "subStruct"

	// StructureIDManifest is the StructureID (in terms of
	// the document #575623) of element 'Manifest'.
	StructureIDManifest = "__KEYM__"
)

var (
	// StrictOrderCheck defines if elements order checks should be performed.
	// For example in the Boot Policy Manifest elements could be in a wrong
	// order. And we still can parse it, but in this way `*Offset` methods
	// could be confusing, since they will show the offset as they will
	// be written (not as they were parsed).
	//
	// We require a strict order because it is explicitly required
	// in the documentation #575623:
	//
	// > The order of the elements and the order of the fields within each
	// > element are architectural and must be followed.
	StrictOrderCheck = true
)
