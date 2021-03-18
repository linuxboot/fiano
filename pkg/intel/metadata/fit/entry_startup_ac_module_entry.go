package fit

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/9elements/converged-security-suite/v2/pkg/errors"
)

// See the section "A.1" of the specification
// "Intel ® Trusted Execution Technology (Intel ® TXT)"
// https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html

// EntrySACMDataInterface is the interface of a startup AC module
// data (of any version)
type EntrySACMDataInterface interface {

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
	ACHeaderVersion0 = ACModuleHeaderVersion(0x0000)

	// ACHeaderVersion3 is version "3.0 – for SINIT ACM of converge of BtG and TXT"
	ACHeaderVersion3 = ACModuleHeaderVersion(0x0300)
)

// ACChipsetID defines the module release identifier
type ACChipsetID uint16

// ACFlags defines the module-specific flags
type ACFlags uint16

// ACModuleVendor defines the module vendor identifier
type ACModuleVendor uint32

// BCDDate is a date in format ("year.month.day").
type BCDDate uint32

// SizeM4 is a size in multiples of four bytes
type SizeM4 uint32

// Size return the size in bytes
func (size SizeM4) Size() uint64   { return uint64(size) << 2 }
func (size SizeM4) String() string { return fmt.Sprintf("%d*4", uint32(size)) }

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

type SACMFieldOffset uint32

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

func (entryData *EntrySACMDataCommon) GetModuleType() ACModuleType { return entryData.ModuleType }
func (entryData *EntrySACMDataCommon) GetModuleSubType() ACModuleSubType {
	return entryData.ModuleSubType
}
func (entryData *EntrySACMDataCommon) GetHeaderLen() SizeM4 { return entryData.HeaderLen }
func (entryData *EntrySACMDataCommon) GetHeaderVersion() ACModuleHeaderVersion {
	return entryData.HeaderVersion
}
func (entryData *EntrySACMDataCommon) GetChipsetID() ACChipsetID       { return entryData.ChipsetID }
func (entryData *EntrySACMDataCommon) GetFlags() ACFlags               { return entryData.Flags }
func (entryData *EntrySACMDataCommon) GetModuleVendor() ACModuleVendor { return entryData.ModuleVendor }
func (entryData *EntrySACMDataCommon) GetDate() BCDDate                { return entryData.Date }
func (entryData *EntrySACMDataCommon) GetSize() SizeM4                 { return entryData.Size }
func (entryData *EntrySACMDataCommon) GetTXTSVN() TXTSVN               { return entryData.TXTSVN }
func (entryData *EntrySACMDataCommon) GetSESVN() SESVN                 { return entryData.SESVN }
func (entryData *EntrySACMDataCommon) GetCodeControl() CodeControl     { return entryData.CodeControl }
func (entryData *EntrySACMDataCommon) GetErrorEntryPoint() ErrorEntryPoint {
	return entryData.ErrorEntryPoint
}
func (entryData *EntrySACMDataCommon) GetGDTLimit() GDTLimit       { return entryData.GDTLimit }
func (entryData *EntrySACMDataCommon) GetGDTBasePtr() GDTBasePtr   { return entryData.GDTBasePtr }
func (entryData *EntrySACMDataCommon) GetSegSel() SegSel           { return entryData.SegSel }
func (entryData *EntrySACMDataCommon) GetEntryPoint() EntryPoint   { return entryData.EntryPoint }
func (entryData *EntrySACMDataCommon) GetReserved2() [64]byte      { return entryData.Reserved2 }
func (entryData *EntrySACMDataCommon) GetKeySize() SizeM4          { return entryData.KeySize }
func (entryData *EntrySACMDataCommon) GetScratchSize() SizeM4      { return entryData.ScratchSize }
func (entryData *EntrySACMDataCommon) GetRSAPubKey() rsa.PublicKey { return rsa.PublicKey{} }
func (entryData *EntrySACMDataCommon) GetRSAPubExp() uint32        { return 0 }
func (entryData *EntrySACMDataCommon) GetRSASig() []byte           { return nil }
func (entryData *EntrySACMDataCommon) RSASigBinaryOffset() uint64  { return 0 }
func (entryData *EntrySACMDataCommon) GetScratch() []byte          { return nil }

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

type EntrySACMData0 struct {
	EntrySACMDataCommon

	RSAPubKey [256]byte
	RSAPubExp [4]byte
	RSASig    [256]byte
	Scratch   [572]byte
}

var entrySACMData0Size = uint(binary.Size(EntrySACMData0{}))

func (entryData *EntrySACMData0) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: int(entryData.GetRSAPubExp()),
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}
func (entryData *EntrySACMData0) GetRSAPubExp() uint32 {
	return binary.LittleEndian.Uint32(entryData.RSAPubExp[:])
}
func (entryData *EntrySACMData0) GetRSASig() []byte { return entryData.RSASig[:] }
func (entryData *EntrySACMData0) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntrySACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey)) +
		uint64(binary.Size(entryData.RSAPubExp))
}
func (entryData *EntrySACMData0) GetScratch() []byte { return entryData.Scratch[:] }

type EntrySACMData3 struct {
	EntrySACMDataCommon

	RSAPubKey [384]byte
	RSASig    [384]byte
	Scratch   [832]byte
}

var entrySACMData3Size = uint(binary.Size(EntrySACMData3{}))

func (entryData *EntrySACMData3) GetRSAPubKey() rsa.PublicKey {
	pubKey := rsa.PublicKey{
		N: big.NewInt(0),
		E: 0x10001, // see Table 9. "RSAPubExp" of https://www.intel.com/content/www/us/en/software-developers/txt-software-development-guide.html
	}
	pubKey.N.SetBytes(entryData.RSAPubKey[:])
	return pubKey
}
func (entryData *EntrySACMData3) GetRSASig() []byte { return entryData.RSASig[:] }
func (entryData *EntrySACMData3) RSASigBinaryOffset() uint64 {
	return uint64(binary.Size(entryData.EntrySACMDataCommon)) +
		uint64(binary.Size(entryData.RSAPubKey))
}
func (entryData *EntrySACMData3) GetScratch() []byte { return entryData.Scratch[:] }

type EntrySACMData struct {
	EntrySACMDataInterface

	UserArea []byte
}

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
	}
	return nil
}

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

func EntrySACMParseSize(b []byte) (uint32, error) {
	sizeFieldOffset := EntrySACMDataCommon{}.SizeBinaryOffset()
	if int(sizeFieldOffset) >= len(b)-4 {
		return 0, &errors.ErrEndLessThanStart{StartIdx: int(sizeFieldOffset), EndIdx: len(b) - 4}
	}
	return binary.LittleEndian.Uint32(b[sizeFieldOffset:]) << 2, nil
}

func (entry *EntrySACM) ParseData() (*EntrySACMData, error) {
	common := EntrySACMDataCommon{}
	if err := binary.Read(bytes.NewReader(entry.DataBytes), binary.LittleEndian, &common); err != nil {
		return nil, fmt.Errorf("unable to parse startup AC module entry: %w", err)
	}
	result := &EntrySACMData{EntrySACMDataInterface: &common, UserArea: nil}

	var requiredKeySize uint64
	switch common.HeaderVersion {
	case ACHeaderVersion0:
		result.EntrySACMDataInterface = &EntrySACMData0{}
		requiredKeySize = uint64(len(EntrySACMData0{}.RSAPubKey))
	case ACHeaderVersion3:
		result.EntrySACMDataInterface = &EntrySACMData3{}
		requiredKeySize = uint64(len(EntrySACMData3{}.RSAPubKey))
	default:
		return result, &ErrUnknownACMHeaderVersion{ACHeaderVersion: common.HeaderVersion}
	}

	if common.KeySize.Size() != requiredKeySize {
		return result, &ErrACMInvalidKeySize{ExpectedKeySize: requiredKeySize, RealKeySize: common.KeySize.Size()}
	}

	if err := binary.Read(bytes.NewReader(entry.DataBytes), binary.LittleEndian, result.EntrySACMDataInterface); err != nil {
		return result, fmt.Errorf("cannot parse AC header of version %v: %w", common.HeaderVersion, err)
	}

	// `UserArea` has variable length and therefore was not included into
	// `EntrySACMData0` and `EntrySACMData3`, but it is in the tail,
	// so we just calculate the startIndex as the end of
	// EntrySACMData0/EntrySACMData3.
	userAreaStartIdx := binary.Size(result.EntrySACMDataInterface)
	userAreaEndIdx := result.EntrySACMDataInterface.GetSize().Size()
	result.UserArea = entry.DataBytes[userAreaStartIdx:userAreaEndIdx]

	return result, nil
}

type entrySACMJSON struct {
	Headers        *EntryHeaders
	DataParsed     *EntrySACMData `json:",omitempty"`
	DataNotParsed  []byte         `json:"DataNotParsedBase64,omitempty"`
	HeadersErrors  []error
	DataParseError error
}

func (entry *EntrySACM) MarshalJSON() ([]byte, error) {
	result := entrySACMJSON{}
	result.Headers = entry.Headers
	result.DataParsed, result.DataParseError = entry.ParseData()
	result.HeadersErrors = make([]error, len(entry.HeadersErrors))
	copy(result.HeadersErrors, entry.HeadersErrors)
	result.DataNotParsed = entry.DataBytes
	return json.Marshal(&result)
}

func (entry *EntrySACM) UnmarshalJSON(b []byte) error {
	result := entrySACMJSON{}
	err := json.Unmarshal(b, &result)
	if err != nil {
		return err
	}
	entry.Headers = result.Headers
	entry.HeadersErrors = result.HeadersErrors
	entry.DataBytes = result.DataNotParsed
	return nil
}
