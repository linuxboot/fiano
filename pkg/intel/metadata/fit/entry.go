package fit

import (
	"fmt"
)

// Entry is the interface common to any FIT entry
type Entry interface {
	fmt.GoStringer

	// GetType returns the type of the FIT entry
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

// Each of these types are extendable, see files "entry_*.go":

// EntryFITHeaderEntry represents a FIT entry of type "FIT Header Entry" (0x00)
type EntryFITHeaderEntry struct{ EntryBase }

// EntryMicrocodeUpdateEntry represents a FIT entry of type "Microcode Update Entry" (0x01)
type EntryMicrocodeUpdateEntry struct{ EntryBase }

// EntrySACM represents a FIT entry of type "Startup AC Module Entry" (0x02)
type EntrySACM struct{ EntryBase }

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

// EntryJMP_DebugPolicy represents a FIT entry of type "JMP $ Debug Policy" (0x2F)
//noinspection GoSnakeCaseUsage
type EntryJMP_DebugPolicy struct{ EntryBase }

// EntrySkip represents a FIT entry of type "Unused Entry (skip)" (0x7F)
type EntrySkip struct{ EntryBase }

// EntryUnknown represents an unknown FIT entry type.
type EntryUnknown struct{ EntryBase }
