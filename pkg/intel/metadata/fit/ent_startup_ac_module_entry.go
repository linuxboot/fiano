// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fit

import (
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/linuxboot/fiano/pkg/intel/metadata/fit/check"
	"github.com/xaionaro-go/bytesextra"
)

// EntryStartupACM represents a FIT entry of type "Startup AC Module Entry" (0x02)
type EntryStartupACM struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntryStartupACM)(nil)

func (entry *EntryStartupACM) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	offset, err := entry.Headers.getDataSegmentOffset(firmware)
	if err != nil {
		return 0, fmt.Errorf("unable to detect data segment offset: %w", err)
	}

	// See point "7" of "2.7" of the specification: the size field is
	// always zero. So we parsing the size from it's data right now:
	var size uint32
	size, err = EntryStartupACMParseSizeFrom(firmware, offset)
	if err != nil {
		return 0, fmt.Errorf("unable to detect data segment size: %w", err)
	}
	return uint64(size), nil
}

var _ EntryCustomRecalculateHeaderser = (*EntryStartupACM)(nil)

func (entry *EntryStartupACM) CustomRecalculateHeaders() error {
	// See 4.4.7 of the FIT specification.
	entry.Headers.Size.SetUint32(0)
	return nil
}

// See the section "A.1" of the specification
// "Intel ® Trusted Execution Technology (Intel ® TXT)"
// https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html

// EntryStartupACMDataInterface is the interface of a startup AC module
// data (of any version)
type EntryStartupACMDataInterface interface {
	io.ReadWriter
	io.ReaderFrom
	io.WriterTo

	// Field getters:

	GetModuleType() ACModuleType
	GetModuleSubType() ACModuleSubType
	GetHeaderLen() SizeM4
	GetHeaderVersion() ACModuleHeaderVersion
	GetChipsetID() ACChipsetID
	GetFlags() ACFlags
	GetModuleVendor() ACModuleVendor
	GetDate() BCDDate
	GetSize() SizeM4
	GetTXTSVN() TXTSVN
	GetSESVN() SESVN
	GetCodeControl() CodeControl
	GetErrorEntryPoint() ErrorEntryPoint
	GetGDTLimit() GDTLimit
	GetGDTBasePtr() GDTBasePtr
	GetSegSel() SegSel
	GetEntryPoint() EntryPoint
	GetReserved2() [64]byte
	GetKeySize() SizeM4
	GetScratchSize() SizeM4
	GetRSAPubKey() rsa.PublicKey
	GetRSAPubExp() uint32
	GetRSASig() []byte
	GetScratch() []byte

	// Auxiliary methods:
	RSASigBinaryOffset() uint64

	// DateBinaryOffset returns the offset of the field 'Date'
	// relatively to the beginning of the structure in the binary
	// format (see 'encoding/binary').
	DateBinaryOffset() uint
}

// ACModuleType defines the type of AC module
type ACModuleType uint16

// ACModuleSubType defines the subtype of AC module (0 - TXT ACM; 1 - S-ACM)
type ACModuleSubType uint16

// ACModuleHeaderVersion defines module format version:
// * 0.0 – for SINIT ACM before 2017
// * 3.0 – for SINIT ACM of converge of BtG and TXT
type ACModuleHeaderVersion uint32

const (
	// ACHeaderVersion0 is version "0.0 – for SINIT ACM before 2017"
	ACHeaderVersion0 = ACModuleHeaderVersion(0x00000000)

	// ACHeaderVersion3 is version "3.0 – for SINIT ACM of converge of BtG and TXT"
	ACHeaderVersion3 = ACModuleHeaderVersion(0x00030000)
)

func (ver ACModuleHeaderVersion) GoString() string {
	return fmt.Sprintf("0x%08X", ver)
}

// ACChipsetID defines the module release identifier
type ACChipsetID uint16

// ACFlags defines the module-specific flags
type ACFlags uint16

// ACModuleVendor defines the module vendor identifier
type ACModuleVendor uint32

// BCDDate is a date in format ("year.month.day")
type BCDDate uint32

// SizeM4 is a size in multiples of four bytes
type SizeM4 uint32

// Size return the size in bytes
func (size SizeM4) Size() uint64      { return uint64(size) << 2 }
func (size SizeM4) String() string    { return fmt.Sprintf("%d*4", uint32(size)) }
func (size *SizeM4) SetSize(v uint64) { *size = SizeM4(v >> 2) }

// TXTSVN is the TXT Security Version Number
type TXTSVN uint16

// SESVN is the Software Guard Extensions (Secure Enclaves) Security Version Number
type SESVN uint16

// CodeControl is the authenticated code control flags
type CodeControl uint32

// ErrorEntryPoint is the error response entry point offset (bytes)
type ErrorEntryPoint uint32

// Pointer returns the value of ErrorEntryPoint as a pointer which
// could be used for pointer arithmetics.
func (ptr ErrorEntryPoint) Pointer() uint64 { return uint64(ptr) }

// GDTLimit is the GDT limit (defines last byte of GDT)
type GDTLimit uint32

// GDTBasePtr is the GDT base pointer offset (bytes)
type GDTBasePtr uint32

// Offset returns the GDTBasePtr value as a pointer which
// could be used for pointer arithmetics.
func (ptr GDTBasePtr) Offset() uint64 { return uint64(ptr) }

// SegSel is the segment selector initializer
type SegSel uint32

// EntryPoint is the authenticated code entry point offset (bytes)
type EntryPoint uint32

// EntryStartupACMDataCommon is the common part from the beginning of a startup AC module
// entry of any version.
type EntryStartupACMDataCommon struct {
	ModuleType      ACModuleType
	ModuleSubType   ACModuleSubType
	HeaderLen       SizeM4
	HeaderVersion   ACModuleHeaderVersion
	ChipsetID       ACChipsetID
	Flags           ACFlags
	ModuleVendor    ACModuleVendor
	Date            BCDDate
	Size            SizeM4
	TXTSVN          TXTSVN
	SESVN           SESVN
	CodeControl     CodeControl
	ErrorEntryPoint ErrorEntryPoint
	GDTLimit        GDTLimit
	GDTBasePtr      GDTBasePtr
	SegSel          SegSel
	EntryPoint      EntryPoint
	Reserved2       [64]byte
	KeySize         SizeM4
	ScratchSize     SizeM4
}

var entryStartupACMDataCommonSize = uint(binary.Size(EntryStartupACMDataCommon{}))

// Read parses the ACM common headers
func (entryData *EntryStartupACMDataCommon) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM common headers
func (entryData *EntryStartupACMDataCommon) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entryStartupACMDataCommonSize), nil
}

// Write compiles the ACM common headers into a binary representation
func (entryData *EntryStartupACMDataCommon) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the ACM common headers into a binary representation
func (entryData *EntryStartupACMDataCommon) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entryStartupACMDataCommonSize), nil
}

// GetModuleType returns the type of AC module
func (entryData *EntryStartupACMDataCommon) GetModuleType() ACModuleType { return entryData.ModuleType }

// GetModuleSubType returns the subtype of AC module (0 - TXT ACM; 1 - S-ACM)
func (entryData *EntryStartupACMDataCommon) GetModuleSubType() ACModuleSubType {
	return entryData.ModuleSubType
}

// GetHeaderLen returns HeaderLen field value
func (entryData *EntryStartupACMDataCommon) GetHeaderLen() SizeM4 { return entryData.HeaderLen }

// GetHeaderVersion returns module format version:
// * 0.0 – for SINIT ACM before 2017
// * 3.0 – for SINIT ACM of converge of BtG and TXT
func (entryData *EntryStartupACMDataCommon) GetHeaderVersion() ACModuleHeaderVersion {
	return entryData.HeaderVersion
}

// GetChipsetID returns ChipsetID field value
func (entryData *EntryStartupACMDataCommon) GetChipsetID() ACChipsetID { return entryData.ChipsetID }

// GetFlags returns Flags field value (the module-specific flags)
func (entryData *EntryStartupACMDataCommon) GetFlags() ACFlags { return entryData.Flags }

// GetModuleVendor returns ModuleVendor field value
func (entryData *EntryStartupACMDataCommon) GetModuleVendor() ACModuleVendor {
	return entryData.ModuleVendor
}

// GetDate returns Date field value ("year.month.day")
func (entryData *EntryStartupACMDataCommon) GetDate() BCDDate { return entryData.Date }

// GetSize returns Size field value (the size in multiples of four bytes)
func (entryData *EntryStartupACMDataCommon) GetSize() SizeM4 { return entryData.Size }

// GetTXTSVN returns TXT security version number
func (entryData *EntryStartupACMDataCommon) GetTXTSVN() TXTSVN { return entryData.TXTSVN }

// GetSESVN returns Software Guard Extensions (Secure Enclaves) Security Version Number
func (entryData *EntryStartupACMDataCommon) GetSESVN() SESVN { return entryData.SESVN }

// GetCodeControl returns the authenticated code control flags
func (entryData *EntryStartupACMDataCommon) GetCodeControl() CodeControl {
	return entryData.CodeControl
}

// GetErrorEntryPoint returns error entry point field value
func (entryData *EntryStartupACMDataCommon) GetErrorEntryPoint() ErrorEntryPoint {
	return entryData.ErrorEntryPoint
}

// GetGDTLimit returns GDTLimit field value
func (entryData *EntryStartupACMDataCommon) GetGDTLimit() GDTLimit { return entryData.GDTLimit }

// GetGDTBasePtr returns the GDT base pointer offset (bytes)
func (entryData *EntryStartupACMDataCommon) GetGDTBasePtr() GDTBasePtr { return entryData.GDTBasePtr }

// GetSegSel the segment selector initializer
func (entryData *EntryStartupACMDataCommon) GetSegSel() SegSel { return entryData.SegSel }

// GetEntryPoint returns the authenticated code entry point offset (bytes)
func (entryData *EntryStartupACMDataCommon) GetEntryPoint() EntryPoint { return entryData.EntryPoint }

// GetReserved2 returns the Reserved2 field value
func (entryData *EntryStartupACMDataCommon) GetReserved2() [64]byte { return entryData.Reserved2 }

// GetKeySize returns the KeySize field value (the size in multiples of four bytes)
func (entryData *EntryStartupACMDataCommon) GetKeySize() SizeM4 { return entryData.KeySize }

// GetScratchSize returns the ScratchSize field value (the size in multiples of four bytes)
func (entryData *EntryStartupACMDataCommon) GetScratchSize() SizeM4 { return entryData.ScratchSize }

// GetRSAPubKey returns the RSA public key
func (entryData *EntryStartupACMDataCommon) GetRSAPubKey() rsa.PublicKey { return rsa.PublicKey{} }

// GetRSAPubExp returns the RSA exponent
func (entryData *EntryStartupACMDataCommon) GetRSAPubExp() uint32 { return 0 }

// GetRSASig returns the RSA signature.
func (entryData *EntryStartupACMDataCommon) GetRSASig() []byte { return nil }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntryStartupACMDataCommon) RSASigBinaryOffset() uint64 { return 0 }

// GetScratch returns the Scratch field value
func (entryData *EntryStartupACMDataCommon) GetScratch() []byte { return nil }

// HeaderVersionBinaryOffset returns the offset of the field 'HeaderVersion'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntryStartupACMDataCommon) HeaderVersionBinaryOffset() uint {
	return 8
}

// DateBinaryOffset returns the offset of the field 'Date'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntryStartupACMDataCommon) DateBinaryOffset() uint {
	return 20
}

// SizeBinaryOffset returns the offset of the field 'Size'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntryStartupACMDataCommon) SizeBinaryOffset() uint {
	return 24
}

// TXTSVNBinaryOffset returns the offset of the field 'TXTSVN'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData *EntryStartupACMDataCommon) TXTSVNBinaryOffset() uint64 {
	return 28
}

// KeySizeBinaryOffset returns the offset of the field 'KeySize'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntryStartupACMDataCommon) KeySizeBinaryOffset() uint {
	return 120
}

// EntryStartupACMData0 is the structure for ACM of version 0.0.
type EntryStartupACMData0 struct {
	EntryStartupACMDataCommon

	RSAPubKey [256]byte
	RSAPubExp [4]byte
	RSASig    [256]byte
	Scratch   [572]byte
}

var entryStartupACMData0Size = uint(binary.Size(EntryStartupACMData0{}))

// Read parses the ACM v0 headers
func (entryData *EntryStartupACMData0) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM v0 headers
func (entryData *EntryStartupACMData0) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entryStartupACMData0Size), nil
}

// Write compiles the ACM v0 headers into a binary representation
func (entryData *EntryStartupACMData0) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the ACM v0 headers into a binary representation
func (entryData *EntryStartupACMData0) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entryStartupACMData0Size), nil
}

// GetRSAPubKey returns the RSA public key
func (entryData *EntryStartupACMData0) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: int(entryData.GetRSAPubExp()),
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}

// GetRSAPubExp returns the RSA exponent
func (entryData *EntryStartupACMData0) GetRSAPubExp() uint32 {
	return binary.LittleEndian.Uint32(entryData.RSAPubExp[:])
}

// GetRSASig returns the RSA signature.
func (entryData *EntryStartupACMData0) GetRSASig() []byte { return entryData.RSASig[:] }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntryStartupACMData0) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntryStartupACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey)) +
		uint64(binary.Size(entryData.RSAPubExp))
}

// GetScratch returns the Scratch field value
func (entryData *EntryStartupACMData0) GetScratch() []byte { return entryData.Scratch[:] }

// EntryStartupACMData3 is the structure for ACM of version 3.0
type EntryStartupACMData3 struct {
	EntryStartupACMDataCommon

	RSAPubKey [384]byte
	RSASig    [384]byte
	Scratch   [832]byte
}

var entryStartupACMData3Size = uint(binary.Size(EntryStartupACMData3{}))

// Read parses the ACM v3 headers
func (entryData *EntryStartupACMData3) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM v3 headers
func (entryData *EntryStartupACMData3) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entryStartupACMData3Size), nil
}

// Write compiles the StartupACM v3 headers into a binary representation
func (entryData *EntryStartupACMData3) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the StartupACM v3 headers into a binary representation
func (entryData *EntryStartupACMData3) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entryStartupACMData3Size), nil
}

// GetRSAPubKey returns the RSA public key
func (entryData *EntryStartupACMData3) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: 0x10001, // see Table 9. "RSAPubExp" of https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}

// GetRSASig returns the RSA signature.
func (entryData *EntryStartupACMData3) GetRSASig() []byte { return entryData.RSASig[:] }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntryStartupACMData3) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntryStartupACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey))
}

// GetScratch returns the Scratch field value
func (entryData *EntryStartupACMData3) GetScratch() []byte { return entryData.Scratch[:] }

// EntryStartupACMData combines the structure for ACM and the user area.
type EntryStartupACMData struct {
	EntryStartupACMDataInterface

	UserArea []byte
}

// Read parses the ACM
func (entryData *EntryStartupACMData) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM
func (entryData *EntryStartupACMData) ReadFrom(r io.Reader) (int64, error) {
	parsedEntryData, err := ParseStartupACMData(r)
	if err != nil {
		return -1, err
	}
	*entryData = *parsedEntryData
	return int64(binary.Size(entryData.EntryStartupACMDataInterface) + len(entryData.UserArea)), nil
}

// Write compiles the StartupACM into a binary representation
func (entryData *EntryStartupACMData) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the StartupACM into a binary representation
func (entryData *EntryStartupACMData) WriteTo(w io.Writer) (int64, error) {
	totalN, err := entryData.EntryStartupACMDataInterface.WriteTo(w)
	if err != nil {
		return -1, err
	}
	n, err := w.Write(entryData.UserArea)
	if n >= 0 {
		totalN += int64(n)
	}
	if err != nil {
		return totalN, fmt.Errorf("unable to write UserArea: %w", err)
	}
	if n != len(entryData.UserArea) {
		return totalN, fmt.Errorf("unable to complete writing UserArea: %d != %d: %w", n, len(entryData.UserArea), err)
	}
	return totalN, nil
}

// GetCommon returns the common part of the structures for different ACM versions.
func (entryData *EntryStartupACMData) GetCommon() *EntryStartupACMDataCommon {
	if entryData == nil {
		return nil
	}
	switch data := entryData.EntryStartupACMDataInterface.(type) {
	case *EntryStartupACMDataCommon:
		return data
	case *EntryStartupACMData0:
		return &data.EntryStartupACMDataCommon
	case *EntryStartupACMData3:
		return &data.EntryStartupACMDataCommon
	}
	return nil
}

// EntryStartupACMParseSizeFrom parses ACM structure size
func EntryStartupACMParseSizeFrom(r io.ReadSeeker, offset uint64) (uint32, error) {
	sizeFieldLocalOffset := EntryStartupACMDataCommon{}.SizeBinaryOffset()
	sizeFieldOffset := int64(offset) + int64(sizeFieldLocalOffset)
	_, err := r.Seek(sizeFieldOffset, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("unable to seek(%d, start): %w", sizeFieldOffset, err)
	}
	var result uint32
	err = binary.Read(r, binary.LittleEndian, &result)
	if err != nil {
		return 0, fmt.Errorf("unable to read: %w", err)
	}
	return result << 2, nil
}

// EntryStartupACMParseSize parses ACM structure size
func EntryStartupACMParseSize(b []byte) (uint32, error) {
	sizeFieldOffset := EntryStartupACMDataCommon{}.SizeBinaryOffset()
	if int(sizeFieldOffset) >= len(b)-4 {
		return 0, &check.ErrEndLessThanStart{StartIdx: int(sizeFieldOffset), EndIdx: len(b) - 4}
	}
	return binary.LittleEndian.Uint32(b[sizeFieldOffset:]) << 2, nil
}

// ParseData parses StartupACM entry and returns EntryStartupACMData.
func (entry *EntryStartupACM) ParseData() (*EntryStartupACMData, error) {
	entryData := EntryStartupACMData{}
	_, err := entryData.Read(entry.DataSegmentBytes)
	if err != nil {
		return nil, err
	}
	return &entryData, nil
}

// ParseStartupACMData parses StartupACM entry and returns EntryStartupACMData.
func ParseStartupACMData(r io.Reader) (*EntryStartupACMData, error) {

	// Read common headers

	common := EntryStartupACMDataCommon{}
	if _, err := common.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("unable to parse startup AC module entry: %w", err)
	}
	result := &EntryStartupACMData{EntryStartupACMDataInterface: &common, UserArea: nil}

	var requiredKeySize uint64
	switch common.HeaderVersion {
	case ACHeaderVersion0:
		result.EntryStartupACMDataInterface = &EntryStartupACMData0{EntryStartupACMDataCommon: common}
		requiredKeySize = uint64(len(EntryStartupACMData0{}.RSAPubKey))
	case ACHeaderVersion3:
		result.EntryStartupACMDataInterface = &EntryStartupACMData3{EntryStartupACMDataCommon: common}
		requiredKeySize = uint64(len(EntryStartupACMData3{}.RSAPubKey))
	default:
		return result, &ErrUnknownACMHeaderVersion{ACHeaderVersion: common.HeaderVersion}
	}

	if common.KeySize.Size() != requiredKeySize {
		return result, &ErrACMInvalidKeySize{ExpectedKeySize: requiredKeySize, RealKeySize: common.KeySize.Size()}
	}

	// Read version-specific headers
	//
	// Here we need to continue reading from the reader,
	// but in the resulting struct we need to skip the first field (because it contains
	// already read common headers).

	// Creating a substruct without the first field (which is already read)
	t := reflect.TypeOf(result.EntryStartupACMDataInterface).Elem()
	var fieldsToBeFilled []reflect.StructField
	for fieldNum := 1; fieldNum < t.NumField(); fieldNum++ {
		fieldsToBeFilled = append(fieldsToBeFilled, t.Field(fieldNum))
	}
	subStructToBeFilled := reflect.New(reflect.StructOf(fieldsToBeFilled))
	// Reading the substruct
	if err := binary.Read(r, binary.LittleEndian, subStructToBeFilled.Interface()); err != nil {
		return result, fmt.Errorf("cannot parse version-specific headers (version 0x%04X): %w", common.HeaderVersion, err)
	}
	// Copying values from the substruct to the headers struct
	subStructToBeFilled = subStructToBeFilled.Elem()
	v := reflect.ValueOf(result.EntryStartupACMDataInterface).Elem()
	for fieldNum := 1; fieldNum < v.NumField(); fieldNum++ {
		v.Field(fieldNum).Set(subStructToBeFilled.Field(fieldNum - 1))
	}

	// Read UserArea

	// `UserArea` has variable length and therefore was not included into
	// `EntryStartupACMData0` and `EntryStartupACMData3`, but it is in the tail,
	// so we just calculate the startIndex as the end of
	// EntryStartupACMData0/EntryStartupACMData3.
	userAreaStartIdx := uint64(binary.Size(result.EntryStartupACMDataInterface))
	userAreaEndIdx := result.EntryStartupACMDataInterface.GetSize().Size()
	if userAreaEndIdx > userAreaStartIdx {
		var err error
		result.UserArea, err = readBytesFromReader(r, userAreaEndIdx-userAreaStartIdx)
		if err != nil {
			return result, fmt.Errorf("unable to read user area: %w", err)
		}
	}

	return result, nil
}

type entryStartupACMJSON struct {
	Headers        *EntryHeaders
	DataParsed     *EntryStartupACMData `json:",omitempty"`
	DataNotParsed  []byte               `json:"DataNotParsedBase64,omitempty"`
	HeadersErrors  []error
	DataParseError error
}

// MarshalJSON implements json.Marshaler
func (entry *EntryStartupACM) MarshalJSON() ([]byte, error) {
	result := entryStartupACMJSON{}
	result.DataParsed, result.DataParseError = entry.ParseData()
	result.Headers = &entry.Headers
	result.HeadersErrors = make([]error, len(entry.HeadersErrors))
	copy(result.HeadersErrors, entry.HeadersErrors)
	result.DataNotParsed = entry.DataSegmentBytes
	return json.Marshal(&result)
}

// UnmarshalJSON implements json.Unmarshaller
func (entry *EntryStartupACM) UnmarshalJSON(b []byte) error {
	result := entryStartupACMJSON{}
	err := json.Unmarshal(b, &result)
	if err != nil {
		return err
	}
	entry.Headers = *result.Headers
	entry.HeadersErrors = result.HeadersErrors
	entry.DataSegmentBytes = result.DataNotParsed
	return nil
}
