// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Entry is the interface common to any FIT entry
type Entry interface {
	fmt.GoStringer

	// SetEntryBase sets EntryBase (which contains metadata of the Entry).
	SetEntryBase(base EntryBase)

	// GetType returns the type of the FIT entry from the headers.
	GetType() EntryType

	// GetHeaders returns the FIT entry headers.
	//
	// See "Table 1-1" in "1.2 Firmware Interface Table" in "Firmware Interface Table" specification:
	//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
	GetHeaders() *EntryHeaders

	// GetDataOffset returns the offset of the data of the entry
	// relatively to the beginning of the firmware image.
	GetDataOffset() uint64

	// GetDataBytes returns the data of the entry.
	GetDataBytes() []byte

	// GetHeadersErrors returns the errors were received while processing
	// the headers of the entry.
	GetHeadersErrors() []error
}

// EntriesByType is a helper to sort a slice of `Entry`-ies by their type/class.
type EntriesByType []Entry

func (entries EntriesByType) Less(i, j int) bool { return entries[i].GetType() < entries[j].GetType() }
func (entries EntriesByType) Swap(i, j int)      { entries[i], entries[j] = entries[j], entries[i] }
func (entries EntriesByType) Len() int           { return len(entries) }

// EntryBase is the common information for any FIT entry
type EntryBase struct {
	Headers       *EntryHeaders
	DataOffset    *uint64 `json:",omitempty"`
	DataBytes     []byte  `json:",omitempty"`
	HeadersErrors []error `json:",omitempty"`
}

// SetEntryBase sets EntryBase (which contains metadata of the Entry).
func (entry *EntryBase) SetEntryBase(base EntryBase) {
	*entry = base
}

// GetType returns the type of the FIT entry
func (entry *EntryBase) GetType() EntryType {
	return entry.Headers.Type()
}

// GetHeaders returns the FIT entry headers.
//
// See "Table 1-1" in "1.2 Firmware Interface Table" in "Firmware Interface Table" specification:
//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
func (entry *EntryBase) GetHeaders() *EntryHeaders {
	return entry.Headers
}

// GetDataOffset returns the offset of the data of the entry
// relatively to the beginning of the firmware image.
func (entry *EntryBase) GetDataOffset() uint64 {
	return *entry.DataOffset
}

// GetDataBytes returns the data of the entry.
func (entry *EntryBase) GetDataBytes() []byte {
	return entry.DataBytes
}

// GetHeadersErrors returns the errors were received while processing
// the headers of the entry.
func (entry *EntryBase) GetHeadersErrors() []error {
	return entry.HeadersErrors
}

// GoString implements fmt.GoStringer
func (entry *EntryBase) GoString() string {
	return entry.Headers.GoString()
}

// RehashEntry recalculates metadata to be consistent with data. For example, it fixes checksum, data size,
// entry type and so on.
func RehashEntry(entry Entry) error {
	if rehasher, ok := entry.(interface{ Rehash() error }); ok {
		err := rehasher.Rehash()
		if err != nil {
			return fmt.Errorf("type-specific Rehash() returned error: %w", err)
		}
	}

	entryType, foundEntryType := EntryTypeOf(entry)
	if !foundEntryType {
		return fmt.Errorf("type %T is not known", entry)
	}

	hdr := entry.GetHeaders()

	// Set Type and IsChecksumValid

	hdr.TypeAndIsChecksumValid.SetType(entryType)
	hdr.TypeAndIsChecksumValid.SetIsChecksumValid(true)

	// Set Version

	switch entryType {
	case EntryTypeTPMPolicyRecord,
		EntryTypeTXTPolicyRecord:
		// See 4.7.4 and 4.9.4 of the FIT specification.
		// noop
	case EntryTypeFITHeaderEntry,
		EntryTypeStartupACModuleEntry,
		EntryTypeDiagnosticACModuleEntry,
		EntryTypeBIOSStartupModuleEntry,
		EntryTypeBIOSPolicyRecord,
		EntryTypeKeyManifestRecord,
		EntryTypeBootPolicyManifest,
		EntryTypeCSESecureBoot,
		EntryTypeFeaturePolicyDeliveryRecord:
		// See 4.2.6, 4.4.8, 4.5.5, 4.6.12, 4.8.4, 4.10.2, 4.11.3, 4.12.4, 4.13.6 of the FIT specification
		hdr.Version = EntryVersion(0x0100)
	}

	// Set Address, Size and TypeAndIsChecksumValid

	// Keep this consistent with getDataCoordinates()
	// TODO: make these handlers modular
	switch entryType {
	case EntryTypeFITHeaderEntry:
		// See 4.2 of the FIT specification.
		hdr.Address = Address64(binary.LittleEndian.Uint64([]byte("_FIT_   ")))
	case EntryTypeStartupACModuleEntry:
		// See 4.4.7 of the FIT specification.
		hdr.Size.SetUint32(0)
	case EntryTypeTXTPolicyRecord:
		// See 4.9.10 of the FIT specification.
		hdr.TypeAndIsChecksumValid.SetIsChecksumValid(false)
		// See 4.9.11 of the FIT specification.
		hdr.Size.SetUint32(0)
	case EntryTypeDiagnosticACModuleEntry, EntryTypeTPMPolicyRecord:
		return fmt.Errorf("support of %s is not implemented, yet", entryType)
	case EntryTypeBIOSPolicyRecord, EntryTypeKeyManifestRecord, EntryTypeBootPolicyManifest:
		hdr.Size.SetUint32(uint32(len(entry.GetDataBytes())))
	default:
		hdr.Size.SetUint32(uint32(len(entry.GetDataBytes()) >> 4))
	}

	// Set Checksum

	if hdr.TypeAndIsChecksumValid.IsChecksumValid() {
		hdr.Checksum = hdr.CalculateChecksum()
	}

	return nil
}

// Entries are a slice of multiple parsed FIT entries (headers + data)
type Entries []Entry

// Rehash recalculates metadata to be consistent with data. For example, it fixes checksum, data size,
// entry type and so on.
//
// Supposed to be used before Inject or/and InjectTo. Since it is possible to prepare data in entries, then
// call Rehash (to prepare headers consistent with data).
func (entries Entries) Rehash() error {
	if len(entries) == 0 {
		return nil
	}

	beginEntry, ok := entries[0].(*EntryFITHeaderEntry)
	if !ok {
		return fmt.Errorf("the first entry is not a EntryFITHeaderEntry, but %T", entries[0])
	}

	// See point 4.2.5 of the FIT specification
	beginEntry.GetHeaders().Size.SetUint32(uint32(len(entries)))

	for idx, entry := range entries {
		err := RehashEntry(entry)
		if err != nil {
			return fmt.Errorf("unable to rehash FIT entry #%d (%#+v): %w", idx, entry, err)
		}
	}

	return nil
}

// Inject writes FIT headers and data to a firmware image.
//
// What will happen:
// 1. The FIT headers will be written by offset headersOffset.
// 2. The FIT pointer will be written at consts.FITPointerOffset offset from the end of the image.
// 3. Data referenced by FIT headers will be written at offsets accordingly to Address fields (in the headers).
//
// Consider calling Rehash() before Inject()/InjectTo()
func (entries Entries) Inject(b []byte, headersOffset uint64) error {
	return entries.InjectTo(newWriteSeekerWrapper(b), headersOffset)
}

// InjectTo does the same as Inject, but for io.WriteSeeker.
func (entries Entries) InjectTo(r io.WriteSeeker, headersOffset uint64) error {
	return fmt.Errorf("not implemented, yet")
}

// Each of these types are extendable, see files "entry_*.go":

// EntryFITHeaderEntry represents a FIT entry of type "FIT Header Entry" (0x00)
type EntryFITHeaderEntry struct{ EntryBase }

// EntryMicrocodeUpdateEntry represents a FIT entry of type "Microcode Update Entry" (0x01)
type EntryMicrocodeUpdateEntry struct{ EntryBase }

// EntrySACM represents a FIT entry of type "Startup AC Module Entry" (0x02)
type EntrySACM struct{ EntryBase }

// EntryDiagnosticACM represents a FIT entry of type "Diagnostic ACM" (0x03)
type EntryDiagnosticACM struct{ EntryBase }

// EntryBIOSStartupModuleEntry represents a FIT entry of type "BIOS Startup Module Entry" (0x07)
type EntryBIOSStartupModuleEntry struct{ EntryBase }

// EntryTPMPolicyRecord represents a FIT entry of type "TPM Policy Record" (0x08)
type EntryTPMPolicyRecord struct{ EntryBase }

// EntryBIOSPolicyRecord represents a FIT entry of type "BIOS Policy Record" (0x09)
type EntryBIOSPolicyRecord struct{ EntryBase }

// EntryKeyManifestRecord represents a FIT entry of type "Key Manifest Record" (0x0B)
type EntryKeyManifestRecord struct{ EntryBase }

// EntryTXTPolicyRecord represents a FIT entry of type "TXT Policy Record" (0x0A)
type EntryTXTPolicyRecord struct{ EntryBase }

// EntryBootPolicyManifestRecord represents a FIT entry of type "Boot Policy Manifest" (0x0C)
type EntryBootPolicyManifestRecord struct{ EntryBase }

// EntryCSESecureBoot represents a FIT entry of type "CSE Secure Boot" (0x10)
type EntryCSESecureBoot struct{ EntryBase }

// EntryFeaturePolicyDeliveryRecord represents a FIT entry of type "Feature Policy Delivery Record" (0x2D)
type EntryFeaturePolicyDeliveryRecord struct{ EntryBase }

// EntryJMPDebugPolicy represents a FIT entry of type "JMP $ Debug Policy" (0x2F)
type EntryJMPDebugPolicy struct{ EntryBase }

// EntrySkip represents a FIT entry of type "Unused Entry (skip)" (0x7F)
type EntrySkip struct{ EntryBase }

// EntryUnknown represents an unknown FIT entry type.
type EntryUnknown struct{ EntryBase }
