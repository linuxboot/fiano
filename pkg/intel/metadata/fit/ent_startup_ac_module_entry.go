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

// EntrySACM represents a FIT entry of type "Startup AC Module Entry" (0x02)
type EntrySACM struct{ EntryBase }

var _ EntryCustomGetDataSegmentSizer = (*EntrySACM)(nil)

func (entry *EntrySACM) CustomGetDataSegmentSize(firmware io.ReadSeeker) (uint64, error) {
	offset, err := entry.Headers.getDataSegmentOffset(firmware)
	if err != nil {
		return 0, fmt.Errorf("unable to detect data segment offset: %w", err)
	}

	// See point "7" of "2.7" of the specification: the size field is
	// always zero. So we parsing the size from it's data right now:
	var size uint32
	size, err = EntrySACMParseSizeFrom(firmware, offset)
	if err != nil {
		return 0, fmt.Errorf("unable to detect data segment size: %w", err)
	}
	return uint64(size), nil
}

var _ EntryCustomRecalculateHeaderser = (*EntrySACM)(nil)

func (entry *EntrySACM) CustomRecalculateHeaders() error {
	// See 4.4.7 of the FIT specification.
	entry.Headers.Size.SetUint32(0)
	return nil
}

// See the section "A.1" of the specification
// "Intel ® Trusted Execution Technology (Intel ® TXT)"
// https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html

// EntrySACMDataInterface is the interface of a startup AC module
// data (of any version)
type EntrySACMDataInterface interface {
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

	// ACHeaderVersion4 is version "4.0 for SINIT ACM of BtG"
	ACHeaderVersion4 = ACModuleHeaderVersion(0x00040000)
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

// EntrySACMDataCommon is the common part from the beginning of a startup AC module
// entry of any version.
type EntrySACMDataCommon struct {
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

var entrySACMDataCommonSize = uint(binary.Size(EntrySACMDataCommon{}))

// Read parses the ACM common headers
func (entryData *EntrySACMDataCommon) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM common headers
func (entryData *EntrySACMDataCommon) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMDataCommonSize), nil
}

// Write compiles the SACM common headers into a binary representation
func (entryData *EntrySACMDataCommon) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the SACM common headers into a binary representation
func (entryData *EntrySACMDataCommon) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMDataCommonSize), nil
}

// GetModuleType returns the type of AC module
func (entryData *EntrySACMDataCommon) GetModuleType() ACModuleType { return entryData.ModuleType }

// GetModuleSubType returns the subtype of AC module (0 - TXT ACM; 1 - S-ACM)
func (entryData *EntrySACMDataCommon) GetModuleSubType() ACModuleSubType {
	return entryData.ModuleSubType
}

// GetHeaderLen returns HeaderLen field value
func (entryData *EntrySACMDataCommon) GetHeaderLen() SizeM4 { return entryData.HeaderLen }

// GetHeaderVersion returns module format version:
// * 0.0 – for SINIT ACM before 2017
// * 3.0 – for SINIT ACM of converge of BtG and TXT
func (entryData *EntrySACMDataCommon) GetHeaderVersion() ACModuleHeaderVersion {
	return entryData.HeaderVersion
}

// GetChipsetID returns ChipsetID field value
func (entryData *EntrySACMDataCommon) GetChipsetID() ACChipsetID { return entryData.ChipsetID }

// GetFlags returns Flags field value (the module-specific flags)
func (entryData *EntrySACMDataCommon) GetFlags() ACFlags { return entryData.Flags }

// GetModuleVendor returns ModuleVendor field value
func (entryData *EntrySACMDataCommon) GetModuleVendor() ACModuleVendor { return entryData.ModuleVendor }

// GetDate returns Date field value ("year.month.day")
func (entryData *EntrySACMDataCommon) GetDate() BCDDate { return entryData.Date }

// GetSize returns Size field value (the size in multiples of four bytes)
func (entryData *EntrySACMDataCommon) GetSize() SizeM4 { return entryData.Size }

// GetTXTSVN returns TXT security version number
func (entryData *EntrySACMDataCommon) GetTXTSVN() TXTSVN { return entryData.TXTSVN }

// GetSESVN returns Software Guard Extensions (Secure Enclaves) Security Version Number
func (entryData *EntrySACMDataCommon) GetSESVN() SESVN { return entryData.SESVN }

// GetCodeControl returns the authenticated code control flags
func (entryData *EntrySACMDataCommon) GetCodeControl() CodeControl { return entryData.CodeControl }

// GetErrorEntryPoint returns error entry point field value
func (entryData *EntrySACMDataCommon) GetErrorEntryPoint() ErrorEntryPoint {
	return entryData.ErrorEntryPoint
}

// GetGDTLimit returns GDTLimit field value
func (entryData *EntrySACMDataCommon) GetGDTLimit() GDTLimit { return entryData.GDTLimit }

// GetGDTBasePtr returns the GDT base pointer offset (bytes)
func (entryData *EntrySACMDataCommon) GetGDTBasePtr() GDTBasePtr { return entryData.GDTBasePtr }

// GetSegSel the segment selector initializer
func (entryData *EntrySACMDataCommon) GetSegSel() SegSel { return entryData.SegSel }

// GetEntryPoint returns the authenticated code entry point offset (bytes)
func (entryData *EntrySACMDataCommon) GetEntryPoint() EntryPoint { return entryData.EntryPoint }

// GetReserved2 returns the Reserved2 field value
func (entryData *EntrySACMDataCommon) GetReserved2() [64]byte { return entryData.Reserved2 }

// GetKeySize returns the KeySize field value (the size in multiples of four bytes)
func (entryData *EntrySACMDataCommon) GetKeySize() SizeM4 { return entryData.KeySize }

// GetScratchSize returns the ScratchSize field value (the size in multiples of four bytes)
func (entryData *EntrySACMDataCommon) GetScratchSize() SizeM4 { return entryData.ScratchSize }

// GetRSAPubKey returns the RSA public key
func (entryData *EntrySACMDataCommon) GetRSAPubKey() rsa.PublicKey { return rsa.PublicKey{} }

// GetRSAPubExp returns the RSA exponent
func (entryData *EntrySACMDataCommon) GetRSAPubExp() uint32 { return 0 }

// GetRSASig returns the RSA signature.
func (entryData *EntrySACMDataCommon) GetRSASig() []byte { return nil }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntrySACMDataCommon) RSASigBinaryOffset() uint64 { return 0 }

// GetScratch returns the Scratch field value
func (entryData *EntrySACMDataCommon) GetScratch() []byte { return nil }

// HeaderVersionBinaryOffset returns the offset of the field 'HeaderVersion'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntrySACMDataCommon) HeaderVersionBinaryOffset() uint {
	return 8
}

// DateBinaryOffset returns the offset of the field 'Date'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntrySACMDataCommon) DateBinaryOffset() uint {
	return 20
}

// SizeBinaryOffset returns the offset of the field 'Size'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntrySACMDataCommon) SizeBinaryOffset() uint {
	return 24
}

// TXTSVNBinaryOffset returns the offset of the field 'TXTSVN'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData *EntrySACMDataCommon) TXTSVNBinaryOffset() uint64 {
	return 28
}

// KeySizeBinaryOffset returns the offset of the field 'KeySize'
// relatively to the beginning of the structure in the binary
// format (see 'encoding/binary').
func (entryData EntrySACMDataCommon) KeySizeBinaryOffset() uint {
	return 120
}

// EntrySACMData0 is the structure for ACM of version 0.0.
type EntrySACMData0 struct {
	EntrySACMDataCommon

	RSAPubKey [256]byte
	RSAPubExp [4]byte
	RSASig    [256]byte
	Scratch   [572]byte
}

var entrySACMData0Size = uint(binary.Size(EntrySACMData0{}))

// Read parses the ACM v0 headers
func (entryData *EntrySACMData0) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM v0 headers
func (entryData *EntrySACMData0) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMData0Size), nil
}

// Write compiles the SACM v0 headers into a binary representation
func (entryData *EntrySACMData0) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the SACM v0 headers into a binary representation
func (entryData *EntrySACMData0) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMData0Size), nil
}

// GetRSAPubKey returns the RSA public key
func (entryData *EntrySACMData0) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: int(entryData.GetRSAPubExp()),
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}

// GetRSAPubExp returns the RSA exponent
func (entryData *EntrySACMData0) GetRSAPubExp() uint32 {
	return binary.LittleEndian.Uint32(entryData.RSAPubExp[:])
}

// GetRSASig returns the RSA signature.
func (entryData *EntrySACMData0) GetRSASig() []byte { return entryData.RSASig[:] }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntrySACMData0) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntrySACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey)) +
		uint64(binary.Size(entryData.RSAPubExp))
}

// GetScratch returns the Scratch field value
func (entryData *EntrySACMData0) GetScratch() []byte { return entryData.Scratch[:] }

// EntrySACMData3 is the structure for ACM of version 3.0
type EntrySACMData3 struct {
	EntrySACMDataCommon

	RSAPubKey [384]byte
	RSASig    [384]byte
	Scratch   [832]byte
}

var entrySACMData3Size = uint(binary.Size(EntrySACMData3{}))

// Read parses the ACM v3 headers
func (entryData *EntrySACMData3) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM v3 headers
func (entryData *EntrySACMData3) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMData3Size), nil
}

// Write compiles the SACM v3 headers into a binary representation
func (entryData *EntrySACMData3) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the SACM v3 headers into a binary representation
func (entryData *EntrySACMData3) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMData3Size), nil
}

// GetRSAPubKey returns the RSA public key
func (entryData *EntrySACMData3) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: 0x10001, // see Table 9. "RSAPubExp" of https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}

// GetRSASig returns the RSA signature.
func (entryData *EntrySACMData3) GetRSASig() []byte { return entryData.RSASig[:] }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntrySACMData3) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntrySACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey))
}

// GetScratch returns the Scratch field value
func (entryData *EntrySACMData3) GetScratch() []byte { return entryData.Scratch[:] }

// EntrySACMData combines the structure for ACM and the user area.
type EntrySACMData struct {
	EntrySACMDataInterface

	UserArea []byte
}

type EntrySACMData4 struct {
	EntrySACMDataCommon

	RSAPubKey  [384]byte
	RSASig     [384]byte
	XMSSPubKey [64]byte
	XMSSSig    [2692]byte
	Reserved   [60]byte
	Scratch    [3584]byte
}

var entrySACMData4Size = uint(binary.Size(EntrySACMData4{}))

// Read parses the ACM v3 headers
func (entryData *EntrySACMData4) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM v3 headers
func (entryData *EntrySACMData4) ReadFrom(r io.Reader) (int64, error) {
	err := binary.Read(r, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMData3Size), nil
}

// Write compiles the SACM v3 headers into a binary representation
func (entryData *EntrySACMData4) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the SACM v3 headers into a binary representation
func (entryData *EntrySACMData4) WriteTo(w io.Writer) (int64, error) {
	err := binary.Write(w, binary.LittleEndian, entryData)
	if err != nil {
		return -1, err
	}
	return int64(entrySACMData4Size), nil
}

// GetRSAPubKey returns the RSA public key
func (entryData *EntrySACMData4) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: 0x10001, // see Table 9. "RSAPubExp" of https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}

// GetRSASig returns the RSA signature.
func (entryData *EntrySACMData4) GetRSASig() []byte { return entryData.RSASig[:] }

// RSASigBinaryOffset returns the RSA signature offset
func (entryData *EntrySACMData4) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntrySACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey))
}

// GetXMSSPubKey returns the XMSS public key
func (entryData *EntrySACMData4) GetXMSSPubKey() []byte { return entryData.XMSSPubKey[:] }

// GetXMSSSig returns the XMSS signature.
func (entryData *EntrySACMData4) GetXMSSSig() []byte { return entryData.XMSSSig[:] }

// GetScratch returns the Scratch field value
func (entryData *EntrySACMData4) GetScratch() []byte { return entryData.Scratch[:] }

// Read parses the ACM
func (entryData *EntrySACMData) Read(b []byte) (int, error) {
	n, err := entryData.ReadFrom(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// ReadFrom parses the ACM
func (entryData *EntrySACMData) ReadFrom(r io.Reader) (int64, error) {
	parsedEntryData, err := ParseSACMData(r)
	if err != nil {
		return -1, err
	}
	*entryData = *parsedEntryData
	return int64(binary.Size(entryData.EntrySACMDataInterface) + len(entryData.UserArea)), nil
}

// Write compiles the SACM into a binary representation
func (entryData *EntrySACMData) Write(b []byte) (int, error) {
	n, err := entryData.WriteTo(bytesextra.NewReadWriteSeeker(b))
	return int(n), err
}

// WriteTo compiles the SACM into a binary representation
func (entryData *EntrySACMData) WriteTo(w io.Writer) (int64, error) {
	totalN, err := entryData.EntrySACMDataInterface.WriteTo(w)
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
func (entryData *EntrySACMData) GetCommon() *EntrySACMDataCommon {
	if entryData == nil {
		return nil
	}
	switch data := entryData.EntrySACMDataInterface.(type) {
	case *EntrySACMDataCommon:
		return data
	case *EntrySACMData0:
		return &data.EntrySACMDataCommon
	case *EntrySACMData3:
		return &data.EntrySACMDataCommon
	case *EntrySACMData4:
		return &data.EntrySACMDataCommon
	}
	return nil
}

// EntrySACMParseSizeFrom parses SACM structure size
func EntrySACMParseSizeFrom(r io.ReadSeeker, offset uint64) (uint32, error) {
	sizeFieldLocalOffset := EntrySACMDataCommon{}.SizeBinaryOffset()
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

// EntrySACMParseSize parses SACM structure size
func EntrySACMParseSize(b []byte) (uint32, error) {
	sizeFieldOffset := EntrySACMDataCommon{}.SizeBinaryOffset()
	if int(sizeFieldOffset) >= len(b)-4 {
		return 0, &check.ErrEndLessThanStart{StartIdx: int(sizeFieldOffset), EndIdx: len(b) - 4}
	}
	return binary.LittleEndian.Uint32(b[sizeFieldOffset:]) << 2, nil
}

// ParseData parses SACM entry and returns EntrySACMData.
func (entry *EntrySACM) ParseData() (*EntrySACMData, error) {
	entryData := EntrySACMData{}
	_, err := entryData.Read(entry.DataSegmentBytes)
	if err != nil {
		return nil, err
	}
	return &entryData, nil
}

// ParseSACMData parses SACM entry and returns EntrySACMData.
func ParseSACMData(r io.Reader) (*EntrySACMData, error) {

	// Read common headers

	common := EntrySACMDataCommon{}
	if _, err := common.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("unable to parse startup AC module entry: %w", err)
	}
	result := &EntrySACMData{EntrySACMDataInterface: &common, UserArea: nil}

	var requiredKeySize uint64
	switch common.HeaderVersion {
	case ACHeaderVersion0:
		result.EntrySACMDataInterface = &EntrySACMData0{EntrySACMDataCommon: common}
		requiredKeySize = uint64(len(EntrySACMData0{}.RSAPubKey))
	case ACHeaderVersion3:
		result.EntrySACMDataInterface = &EntrySACMData3{EntrySACMDataCommon: common}
		requiredKeySize = uint64(len(EntrySACMData3{}.RSAPubKey))
	case ACHeaderVersion4:
		result.EntrySACMDataInterface = &EntrySACMData4{EntrySACMDataCommon: common}
		requiredKeySize = uint64(len(EntrySACMData4{}.RSAPubKey))
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
	t := reflect.TypeOf(result.EntrySACMDataInterface).Elem()
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
	v := reflect.ValueOf(result.EntrySACMDataInterface).Elem()
	for fieldNum := 1; fieldNum < v.NumField(); fieldNum++ {
		v.Field(fieldNum).Set(subStructToBeFilled.Field(fieldNum - 1))
	}

	// Read UserArea

	// `UserArea` has variable length and therefore was not included into
	// `EntrySACMData0` and `EntrySACMData3/4`, but it is in the tail,
	// so we just calculate the startIndex as the end of
	// EntrySACMData0/EntrySACMData3/4.
	userAreaStartIdx := uint64(binary.Size(result.EntrySACMDataInterface))
	userAreaEndIdx := result.EntrySACMDataInterface.GetSize().Size()
	if userAreaEndIdx > userAreaStartIdx {
		var err error
		result.UserArea, err = readBytesFromReader(r, userAreaEndIdx-userAreaStartIdx)
		if err != nil {
			return result, fmt.Errorf("unable to read user area: %w", err)
		}
	}

	return result, nil
}

type entrySACMJSON struct {
	Headers        *EntryHeaders
	DataParsed     *EntrySACMData `json:",omitempty"`
	DataNotParsed  []byte         `json:"DataNotParsedBase64,omitempty"`
	HeadersErrors  []error
	DataParseError error
}

// MarshalJSON implements json.Marshaler
func (entry *EntrySACM) MarshalJSON() ([]byte, error) {
	result := entrySACMJSON{}
	result.DataParsed, result.DataParseError = entry.ParseData()
	result.Headers = &entry.Headers
	result.HeadersErrors = make([]error, len(entry.HeadersErrors))
	copy(result.HeadersErrors, entry.HeadersErrors)
	result.DataNotParsed = entry.DataSegmentBytes
	return json.Marshal(&result)
}

// UnmarshalJSON implements json.Unmarshaller
func (entry *EntrySACM) UnmarshalJSON(b []byte) error {
	result := entrySACMJSON{}
	err := json.Unmarshal(b, &result)
	if err != nil {
		return err
	}
	entry.Headers = *result.Headers
	entry.HeadersErrors = result.HeadersErrors
	entry.DataSegmentBytes = result.DataNotParsed
	return nil
}
