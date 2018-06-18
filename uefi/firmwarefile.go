package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	uuid "github.com/linuxboot/fiano/uuid"
)

// FVFileType represents the different types possible in an EFI file.
type FVFileType uint8

// UEFI FV File types.
const (
	fvFileTypeAll FVFileType = iota
	fvFileTypeRaw
	fvFileTypeFreeForm
	fvFileTypeSECCore
	fvFileTypePEICore
	fvFileTypeDXECore
	fvFileTypePEIM
	fvFileTypeDriver
	fvFileTypeCombinedPEIMDriver
	fvFileTypeApplication
	fvFileTypeSMM
	fvFileTypeVolumeImage
	fvFileTypeCombinedSMMDXE
	fvFileTypeSMMCore
	fvFileTypeSMMStandalone
	fvFileTypeSMMCoreStandalone
	fvFileTypeOEMMin   FVFileType = 0xC0
	fvFileTypeOEMMax   FVFileType = 0xDF
	fvFileTypeDebugMin FVFileType = 0xE0
	fvFileTypeDebugMax FVFileType = 0xEF
	fvFileTypePad      FVFileType = 0xF0
	fvFileTypeFFSMin   FVFileType = 0xF0
	fvFileTypeFFSMax   FVFileType = 0xFF
)

const (
	// FileHeaderMinLength is the minimum length of a firmware file header.
	FileHeaderMinLength = 0x18
)

// FirmwareFileHeader represents an EFI File header.
type FirmwareFileHeader struct {
	Name           uuid.UUID // This is the GUID of the file.
	IntegrityCheck [2]uint8
	Type           FVFileType
	Attributes     uint8
	Size           [3]uint8
	State          uint8
}

// FirmwareFileHeaderExtended represents an EFI File header with the
// large file attribute set.
// We also use this as the generic header for all EFI files, regardless of whether
// they are actually large. This makes it easier for us to just return one type
// All sizes are also copied into the ExtendedSize field so we only have to check once
type FirmwareFileHeaderExtended struct {
	FirmwareFileHeader
	ExtendedSize uint64
}

// FirmwareFile represents an EFI File.
type FirmwareFile struct {
	Header FirmwareFileHeaderExtended
	buf    []byte
}

// NewFirmwareFile parses a sequence of bytes and returns a FirmwareFile
// object, if a valid one is passed, or an error. If no error is returned and the FirmwareFile
// pointer is nil, it means we've reached the volume free space at the end of the FV.
func NewFirmwareFile(buf []byte) (*FirmwareFile, error) {
	f := FirmwareFile{}
	// Read in standard header.
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &f.Header.FirmwareFileHeader); err != nil {
		return nil, err
	}

	// TODO: Check Attribute flag as well. How important is the attribute flag? we already
	// have FFFFFF in the size
	if f.Header.Size == [3]byte{0xFF, 0xFF, 0xFF} {
		// Extended Header
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ExtendedSize); err != nil {
			return nil, err
		}
		if f.Header.ExtendedSize == 0xFFFFFFFFFFFFFFFF {
			// Start of free space
			// Note: this is not a pad file. Pad files also have valid headers.
			return nil, nil
		}
	} else {
		// Copy small size into big for easier handling.
		// Damn the 3 byte sizes.
		f.Header.ExtendedSize = uint64(f.Header.Size[2])<<16 |
			uint64(f.Header.Size[1])<<8 | uint64(f.Header.Size[0])
	}

	if buflen := len(buf); f.Header.ExtendedSize > uint64(buflen) {
		// Our size is exactly the size of a guid. No error will be returned.
		return nil, fmt.Errorf("File size too big! File with GUID: %v has length %v, but is only %v bytes big",
			f.Header.Name, f.Header.ExtendedSize, buflen)
	}
	// Slice buffer to the correct size.
	f.buf = buf[:f.Header.ExtendedSize]

	return &f, nil
}
