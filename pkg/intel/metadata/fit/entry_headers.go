// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xaionaro-go/bytesextra"
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

	Size Uint24

	// Reserved should always be equal to zero.
	Reserved uint8

	Version EntryVersion

	TypeAndIsChecksumValid TypeAndIsChecksumValid

	Checksum uint8
}

func (hdr EntryHeaders) copy() *EntryHeaders {
	return &hdr
}

// GoString implements fmt.GoStringer.
func (hdr *EntryHeaders) GoString() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("   Address: 0x%x\n", hdr.Address.Pointer()))
	result.WriteString(fmt.Sprintf("   size: 0x%x\n", hdr.Size.Uint32()))
	result.WriteString(fmt.Sprintf("   Version: 0x%x\n", uint16(hdr.Version)))
	result.WriteString(fmt.Sprintf("   Type: 0x%x\n", uint8(hdr.TypeAndIsChecksumValid)))
	result.WriteString(fmt.Sprintf("   Checksum: 0x%x\n", hdr.Checksum))
	return result.String()
}

type entryHeadersForJSON struct {
	Address         uint64
	Size            uint32
	Reserved        uint8 `json:",omitempty"`
	Version         EntryVersion
	Type            EntryType
	IsChecksumValid bool
	Checksum        uint8
}

// MarshalJSON just implements encoding/json.Marshaler
func (hdr EntryHeaders) MarshalJSON() ([]byte, error) {
	return json.Marshal(&entryHeadersForJSON{
		Address:         hdr.Address.Pointer(),
		Size:            hdr.Size.Uint32(),
		Reserved:        hdr.Reserved,
		Version:         hdr.Version,
		Type:            hdr.Type(),
		IsChecksumValid: hdr.IsChecksumValid(),
		Checksum:        hdr.Checksum,
	})
}

// UnmarshalJSON just implements encoding/json.Unmarshaler
func (hdr *EntryHeaders) UnmarshalJSON(b []byte) error {
	var parsed entryHeadersForJSON
	err := json.Unmarshal(b, &parsed)
	if err != nil {
		return err
	}
	*hdr = EntryHeaders{
		Address:  Address64(parsed.Address),
		Reserved: parsed.Reserved,
		Version:  parsed.Version,
		Checksum: parsed.Checksum,
	}
	hdr.Size.SetUint32(parsed.Size)
	hdr.TypeAndIsChecksumValid.SetType(parsed.Type)
	hdr.TypeAndIsChecksumValid.SetIsChecksumValid(parsed.IsChecksumValid)
	return nil
}

// Uint24 is a 24 bit unsigned little-endian integer value.
type Uint24 struct {
	Value [3]byte
}

// Uint32 returns the value as parsed uint32.
//
// If the value is used in "Size" then in the most cases the value should be
// shifted with "<< 4" to get the real size value.
//
// See also the code of EntryHeaders.getDataCoordinates()
func (size Uint24) Uint32() uint32 {
	b := make([]byte, 4)
	copy(b[:], size.Value[:])
	return binary.LittleEndian.Uint32(b)
}

// SetUint32 sets the value. See also Uint32.
func (size *Uint24) SetUint32(newValue uint32) {
	if newValue >= 1<<24 {
		panic(fmt.Errorf("too big integer: %d >= %d", newValue, 1<<24))
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, newValue)
	copy(size.Value[:], b[:])
}

// MarshalJSON just implements encoding/json.Marshaler
func (size Uint24) MarshalJSON() ([]byte, error) {
	return json.Marshal(size.Uint32())
}

// UnmarshalJSON just implements encoding/json.Unmarshaler
func (size *Uint24) UnmarshalJSON(b []byte) error {
	var parsed uint32
	err := json.Unmarshal(b, &parsed)
	if err != nil {
		return err
	}
	if parsed >= 1<<24 {
		return fmt.Errorf("too big integer: %d >= %d", parsed, 1<<24)
	}
	size.SetUint32(parsed)
	return nil
}

// Address64 is a 64bit address type
type Address64 uint64

// Pointer returns the pointer which could be used for pointer arithmetics.
func (addr Address64) Pointer() uint64 { return uint64(addr) }

// Offset returns an offset from the beginning of a firmware of a defined size.
func (addr Address64) Offset(firmwareSize uint64) uint64 {
	return CalculateOffsetFromPhysAddr(addr.Pointer(), firmwareSize)
}

// SetOffset sets the value to a physical address corresponding to
// an offset from the beginning of the firmware.
//
// See also the description of calculatePhysAddrFromOffset.
func (addr *Address64) SetOffset(offset, firmwareSize uint64) {
	physAddr := CalculatePhysAddrFromOffset(offset, firmwareSize)
	*addr = Address64(physAddr)
}

// String implements fmt.Stringer
func (addr Address64) String() string { return fmt.Sprintf("0x%x", addr.Pointer()) }

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

// SetType sets the value of field EntryType ("TYPE" of the FIT entry in terms of
// the specification).
func (f *TypeAndIsChecksumValid) SetType(newType EntryType) {
	if uint(newType) & ^uint(0x7f) != 0 {
		panic(fmt.Errorf("invalid type: 0x%X", newType))
	}
	otherBits := TypeAndIsChecksumValid(uint(*f) & ^uint(0x7f))
	*f = TypeAndIsChecksumValid(newType) | otherBits
}

// SetIsChecksumValid sets the value of field IsChecksumValid ("C_V" of the FIT entry in terms of
// the specification).
func (f *TypeAndIsChecksumValid) SetIsChecksumValid(newValue bool) {
	valueBits := TypeAndIsChecksumValid(0)
	if newValue {
		valueBits = TypeAndIsChecksumValid(0x80)
	}

	otherBits := TypeAndIsChecksumValid(uint(*f) & uint(0x7f))
	*f = valueBits | otherBits
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

// GetEntry returns a full entry (headers + data)
func (hdr EntryHeaders) GetEntry(firmware []byte) Entry {
	return hdr.GetEntryFrom(bytesextra.NewReadWriteSeeker(firmware))
}

// GetEntryFrom returns a full entry (headers + data)
func (hdr EntryHeaders) GetEntryFrom(firmware io.ReadSeeker) Entry {
	return NewEntry(hdr.copy(), firmware)
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

var _ io.Writer = (*EntryHeaders)(nil)

// Write implements io.Writer. It writes the headers in a binary format to `b`.
func (hdr *EntryHeaders) Write(b []byte) (int, error) {
	n, err := hdr.WriteTo(bytes.NewBuffer(b))
	return int(n), err
}

var _ io.WriterTo = (*EntryHeaders)(nil)

// WriteTo implements io.WriterTo. It writes the headers in a binary format to `w`.
func (hdr *EntryHeaders) WriteTo(w io.Writer) (int64, error) {
	if hdr == nil {
		return 0, nil
	}

	err := binary.Write(w, binary.LittleEndian, hdr)
	if err != nil {
		return -1, fmt.Errorf("unable to write headers %#+v: %w", *hdr, err)
	}

	return int64(binary.Size(*hdr)), nil
}

// CalculateChecksum calculates the checksum ("CHKSUM")
// according to point 4.0 of the FIT specification.
func (hdr *EntryHeaders) CalculateChecksum() uint8 {
	_copy := *hdr
	_copy.Checksum = 0

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, _copy); err != nil {
		panic(err)
	}

	result := uint8(0)
	for _, _byte := range buf.Bytes() {
		result += _byte
	}

	return result
}

// getDataSegmentCoordinates returns the offset of the data segment
// associated with the entry.
func (hdr *EntryHeaders) getDataSegmentOffset(firmware io.Seeker) (uint64, error) {
	firmwareSize, err := firmware.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("unable to get the size of the firmware: %w", err)
	}

	return hdr.Address.Offset(uint64(firmwareSize)), nil
}

// mostCommonGetDataSegmentCoordinates returns the length of the data segment
// associated with the entry using the most common rule:
// * The size equals to "Size" multiplied by 16.
//
// This is considered the most common rule for the most FIT entry types. But different types may break it.
func (hdr *EntryHeaders) mostCommonGetDataSegmentSize() uint64 {
	return uint64(hdr.Size.Uint32()) << 4
}
