package fit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/check"
	"github.com/9elements/converged-security-suite/v2/pkg/errors"
	uefiConsts "github.com/9elements/converged-security-suite/v2/pkg/uefi/consts"
)

var (
	entryHeadersSize = uint(binary.Size(EntryHeaders{}))
)

// EntryHeaders implements a "FIT Entry Format".
//
// See "Table 1-1" in "1.2 Firmware Interface Table" in "Firmware Interface Table" specification:
//  * https://www.intel.com/content/dam/www/public/us/en/documents/guides/fit-bios-specification.pdf
//
// Descriptions of the fields are adapted descriptions from the document by the link above.
type EntryHeaders struct {
	// Address is the base address of the firmware component.
	// Must be aligned on 16 byte boundary.
	Address Address64

	Size Size24M16 `json:"Size24M16"`

	// Reserved should always be equal to zero.
	Reserved uint8 `json:",omitempty"`

	Version EntryVersion

	TypeAndIsChecksumValid TypeAndIsChecksumValid

	Checksum uint8 `json:",omitempty"`
}

func (hdr *EntryHeaders) GoString() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("   Address: 0x%x\n", hdr.Address.Pointer()))
	result.WriteString(fmt.Sprintf("   size: 0x%x\n", uint16(hdr.Size.Size())))
	result.WriteString(fmt.Sprintf("   Version: 0x%x\n", uint16(hdr.Version)))
	result.WriteString(fmt.Sprintf("   Type: 0x%x\n", uint8(hdr.TypeAndIsChecksumValid)))
	result.WriteString(fmt.Sprintf("   Checksum: 0x%x\n", hdr.Checksum))
	return result.String()
}

// Size24M16 is a 24 bit value of a size in multiple of 16 bytes
type Size24M16 struct {
	Value [3]byte
}

// Size returns the size in bytes
func (size Size24M16) Size() uint32 {
	b := make([]byte, 4)
	copy(b[:], size.Value[:])
	return binary.LittleEndian.Uint32(b) << 4
}

// Address64 is a 64bit address type
type Address64 uint64

// Pointer returns the pointer which could be used for pointer arithmetics.
func (addr Address64) Pointer() uint64 { return uint64(addr) }
func (addr Address64) String() string  { return fmt.Sprintf("0x%x", addr.Pointer()) }

// EntryVersion contains the component's version number in binary
// coded decimal (BCD) format. For the FIT header entry, the value in this
// field will indicate the revision number of the FIT data structure.
// The upper byte of the revision field indicates the major revision and
// the lower byte indicates the minor revision. The format 0x1234 conveys
// the major number encoded in the first two digits and the minor number
// in the last two with a fixed point assumed in between
type EntryVersion uint16

// Major returns the major part of the entry version
func (ver EntryVersion) Major() uint8 { return uint8(ver & 0xff00 >> 8) }

// Minor returns the minor part of the entry version
func (ver EntryVersion) Minor() uint8 { return uint8(ver & 0xff) }

func (ver EntryVersion) String() string {
	b, _ := ver.MarshalJSON()
	return string(b)
}

type entryVersionStruct struct {
	Major uint8 `json:"maj"`
	Minor uint8 `json:"min,omitempty"`
}

// MarshalJSON just implements encoding/json.Marshaler
func (ver EntryVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(&entryVersionStruct{
		Major: ver.Major(),
		Minor: ver.Minor(),
	})
}

// UnmarshalJSON just implements encoding/json.Unmarshaler
func (ver *EntryVersion) UnmarshalJSON(b []byte) error {
	parsed := entryVersionStruct{}
	err := json.Unmarshal(b, &parsed)
	if err != nil {
		return err
	}
	*ver = EntryVersion(parsed.Major)<<8 | EntryVersion(parsed.Minor)
	return nil
}

// SizeM16 is a size in multiple of 16 bytes (M16).
type SizeM16 uint16

// Size returns the size in bytes
func (size SizeM16) Size() uint     { return uint(size) << 4 }
func (size SizeM16) String() string { return fmt.Sprintf("0x%x*0x10", uint16(size)) }

// TypeAndIsChecksumValid combines two fields:
// * "C_V" -- Checksum Valid bit. This is a one bit field that indicates,
//            whether component has a valid checksum. CPU must ignore
//            "Checksum" field, if C_V bit is not set.
// * EntryType (see "entry_type.go").
type TypeAndIsChecksumValid uint8

// IsChecksumValid returns bit "C_V" of the FIT entry.
//
// A quote from the specification:
// Checksum Valid bit. This is a one bit field that indicates, whether
// component has a valid checksum. CPU must ignore CHKSUM field, if C_V bit is not set.
func (f TypeAndIsChecksumValid) IsChecksumValid() bool {
	return f&0x80 != 0
}

// Type returns field EntryType ("TYPE" of the FIT entry in terms of
// the specification).
func (f TypeAndIsChecksumValid) Type() EntryType {
	return EntryType(f & 0x7f)
}

func (f TypeAndIsChecksumValid) String() string {
	b, _ := f.MarshalJSON()
	return string(b)
}

type typeAndIsChecksumValidStruct struct {
	Type            EntryType `json:"type"`
	IsChecksumValid bool      `json:"isChecksumValid,omitempty"`
}

// MarshalJSON just implements encoding/json.Marshaler
func (f TypeAndIsChecksumValid) MarshalJSON() ([]byte, error) {
	return json.Marshal(&typeAndIsChecksumValidStruct{
		IsChecksumValid: f.IsChecksumValid(),
		Type:            f.Type(),
	})
}

// UnmarshalJSON just implements encoding/json.Unmarshaler
func (f *TypeAndIsChecksumValid) UnmarshalJSON(b []byte) error {
	parsed := typeAndIsChecksumValidStruct{}
	err := json.Unmarshal(b, &parsed)
	if err != nil {
		return err
	}
	if parsed.Type >= 0x80 {
		return fmt.Errorf(`"type" value is too high`)
	}
	*f = TypeAndIsChecksumValid(parsed.Type & 0x7f)
	if parsed.IsChecksumValid {
		*f |= 0x80
	}
	return nil
}

// GetEntry returns a full entry (headers + data).
func (hdr EntryHeaders) GetEntry(firmware []byte) Entry {
	return hdr.newEntryFromBytes(firmware)
}

func (hdr EntryHeaders) GetEntryFrom(firmware io.ReadSeeker, firmwareLength uint64) Entry {
	return hdr.newEntryFromReader(firmware, firmwareLength)
}

func (hdr *EntryHeaders) getDataCoordinates(firmware io.ReadSeeker, firmwareLength uint64) (forcedBytes []byte, startIdx *uint64, dataSize *uint32, errs []error) {
	_startIdx := uefiConsts.CalculateOffsetFromPhysAddr(hdr.Address.Pointer(), firmwareLength)
	_dataSize := hdr.Size.Size()

	switch hdr.Type() {
	case EntryTypeFITHeaderEntry:
		// See "1.2.2" of the specification.
		// FITHeaderEntry contains "_FIT_  " string instead of an address.
		// And we shouldn't do anything in this case.
		return nil, nil, nil, nil
	case EntryTypeStartupACModuleEntry:
		// See point "7" of "2.7" of the specification: the size field is
		// always zero. So we parsing the size from it's data right now:
		var err error
		_dataSize, err = EntrySACMParseSizeFrom(firmware, _startIdx)
		if err != nil {
			return nil, nil, nil, []error{err}
		}
	case EntryTypeTXTPolicyRecord:
		// See "1.2.8" of the specification.
		// The "Address" field is actually the structure in this case :(
		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, &hdr.Address)
		if err != nil {
			return nil, nil, nil, []error{err}
		}
		return buf.Bytes(), nil, nil, nil
	}

	if _dataSize == 0 {
		return nil, nil, nil, []error{fmt.Errorf("data size is zero")}
	}

	return nil, &_startIdx, &_dataSize, nil
}

func (hdr *EntryHeaders) newBaseFromBytes(firmware []byte) (result EntryBase) {
	forcedData, startIdx, dataSize, errs := hdr.getDataCoordinates(bytes.NewReader(firmware), uint64(len(firmware)))
	result = EntryBase{
		Headers:       hdr,
		DataOffset:    startIdx,
		DataBytes:     forcedData,
		HeadersErrors: errs,
	}
	if forcedData != nil || errs != nil || startIdx == nil || dataSize == nil {
		return
	}
	endIdx := *startIdx + uint64(*dataSize)

	if err := check.BytesRange(firmware, int(*startIdx), int(endIdx)); err != nil {
		result.HeadersErrors = append(result.HeadersErrors, err.(errors.MultiError)...)
		return
	}

	result.DataBytes = firmware[*startIdx:endIdx]
	return
}

func (hdr *EntryHeaders) newBaseFromReader(firmware io.ReadSeeker, firmwareLength uint64) (result EntryBase) {
	forcedData, startIdx, dataSize, errs := hdr.getDataCoordinates(firmware, firmwareLength)
	result = EntryBase{
		Headers:       hdr,
		DataOffset:    startIdx,
		DataBytes:     forcedData,
		HeadersErrors: errs,
	}
	if forcedData != nil || errs != nil || startIdx == nil || dataSize == nil {
		return
	}

	_, err := firmware.Seek(int64(*startIdx), io.SeekStart)
	if err != nil {
		result.HeadersErrors = append(result.HeadersErrors, fmt.Errorf("unable to seek(%d): %w", *startIdx, err))
		return
	}

	forcedData = make([]byte, *dataSize)
	n, err := firmware.Read(forcedData)
	if err != nil {
		result.HeadersErrors = append(result.HeadersErrors, fmt.Errorf("unable to read %d bytes at %d: %w", *dataSize, *startIdx, err))
		return
	}
	if n != int(*dataSize) {
		result.HeadersErrors = append(result.HeadersErrors, fmt.Errorf("read length != expected length: %d != %d", n, *dataSize))
		return
	}
	result.DataBytes = forcedData

	return
}

func (hdr *EntryHeaders) newEntryFromReader(firmware io.ReadSeeker, firmwareLength uint64) Entry {
	return hdr.newEntryFromBase(hdr.newBaseFromReader(firmware, firmwareLength))
}

func (hdr *EntryHeaders) newEntryFromBytes(firmware []byte) Entry {
	return hdr.newEntryFromBase(hdr.newBaseFromBytes(firmware))
}

func (hdr *EntryHeaders) newEntryFromBase(entryBase EntryBase) Entry {
	switch hdr.Type() {
	case EntryTypeFITHeaderEntry:
		return &EntryFITHeaderEntry{entryBase}
	case EntryTypeMicrocodeUpdateEntry:
		return &EntryMicrocodeUpdateEntry{entryBase}
	case EntryTypeStartupACModuleEntry:
		return &EntrySACM{entryBase}
	case EntryTypeBIOSStartupModuleEntry:
		return &EntryBIOSStartupModuleEntry{entryBase}
	case EntryTypeTPMPolicyRecord:
		return &EntryTPMPolicyRecord{entryBase}
	case EntryTypeBIOSPolicyRecord:
		return &EntryBIOSPolicyRecord{entryBase}
	case EntryTypeTXTPolicyRecord:
		return &EntryTXTPolicyRecord{entryBase}
	case EntryTypeKeyManifestRecord:
		return &EntryKeyManifestRecord{entryBase}
	case EntryTypeBootPolicyManifest:
		return &EntryBootPolicyManifestRecord{entryBase}
	case EntryTypeCSESecureBoot:
		return &EntryCSESecureBoot{entryBase}
	case EntryTypeFeaturePolicyDeliveryRecord:
		return &EntryFeaturePolicyDeliveryRecord{entryBase}
	case EntryTypeJMP_DebugPolicy:
		return &EntryJMP_DebugPolicy{entryBase}
	case EntryTypeSkip:
		return &EntrySkip{entryBase}
	default:
		return &EntryUnknown{entryBase}
	}
}

// Type returns the type of the FIT entry
func (hdr *EntryHeaders) Type() EntryType {
	return hdr.TypeAndIsChecksumValid.Type()
}

// IsChecksumValid returns if bit "C_V" has value "1".
func (hdr *EntryHeaders) IsChecksumValid() bool {
	return hdr.TypeAndIsChecksumValid.IsChecksumValid()
}

func (hdr *EntryHeaders) String() string {
	return fmt.Sprintf("&%+v", *hdr)
}
