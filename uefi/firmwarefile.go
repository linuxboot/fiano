package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"path/filepath"

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
	// FileHeaderExtMinLength is the minimum length of an extended firmware file header.
	FileHeaderExtMinLength       = 0x20
	emptyBodyChecksum      uint8 = 0xAA
)

// IntegrityCheck holds the two 8 bit checksums for the file header and body separately.
type IntegrityCheck struct {
	Header uint8
	File   uint8
}

type fileAttr uint8

// FirmwareFileHeader represents an EFI File header.
type FirmwareFileHeader struct {
	Name       uuid.UUID // This is the GUID of the file.
	Checksum   IntegrityCheck
	Type       FVFileType
	Attributes fileAttr
	Size       [3]uint8
	State      uint8
}

// Checks if the large file attribute is set
func (a fileAttr) isLarge() bool {
	return a&0x01 != 0
}

// Checks if we need to checksum the file body
func (a fileAttr) hasChecksum() bool {
	return a&0x40 != 0
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
	Header   FirmwareFileHeaderExtended
	Sections []*FileSection

	//Metadata for extraction and recovery
	buf         []byte
	ExtractPath string
	DataOffset  uint64
}

// Assemble assembles the Firmware File from the binary
func (f *FirmwareFile) Assemble() ([]byte, error) {
	var err error
	f.buf, err = ioutil.ReadFile(f.ExtractPath)
	if err != nil {
		return nil, err
	}
	return f.buf, nil
}

// Extract extracts the FFS to the directory passed in.
func (f *FirmwareFile) Extract(parentPath string) error {
	// Dump the binary
	var err error
	// For files we use the GUID as the folder name.
	dirPath := filepath.Join(parentPath, f.Header.Name.String())
	f.ExtractPath, err = ExtractBinary(f.buf, dirPath, fmt.Sprintf("%v.ffs", f.Header.Name))
	if err != nil {
		return err
	}
	// extract the sections
	for _, s := range f.Sections {
		err = s.Extract(dirPath)
		if err != nil {
			return err
		}
	}
	return nil
}

// Validate Firmware File
func (f *FirmwareFile) Validate() []error {
	errs := make([]error, 0)
	buflen := uint64(len(f.buf))
	blankSize := [3]byte{0xFF, 0xFF, 0xFF}
	if buflen < FileHeaderMinLength {
		errs = append(errs, fmt.Errorf("file length too small!, buffer is only %#x bytes long", buflen))
		return errs
	}

	// Size Checks
	fh := &f.Header
	if fh.Size == blankSize {
		if buflen < FileHeaderExtMinLength {
			errs = append(errs, fmt.Errorf("file %v length too small!, buffer is only %#x bytes long for extended header",
				fh.Name, buflen))
			return errs
		}
		if !fh.Attributes.isLarge() {
			errs = append(errs, fmt.Errorf("file %v using extended header, but large attribute is not set",
				fh.Name))
			return errs
		}
	} else if Read3Size(f.Header.Size) != fh.ExtendedSize {
		errs = append(errs, fmt.Errorf("file %v size not copied into extendedsize",
			fh.Name))
		return errs
	}
	if buflen != fh.ExtendedSize {
		errs = append(errs, fmt.Errorf("file %v size mismatch! Size is %#x, buf length is %#x",
			fh.Name, fh.ExtendedSize, buflen))
		return errs
	}

	// Header Checksums
	headerSize := FileHeaderMinLength
	if fh.Attributes.isLarge() {
		headerSize = FileHeaderExtMinLength
	}
	// Sum over header without State and IntegrityCheck.File.
	// To do that we just sum over the whole header and subtract.
	// UEFI PI Spec 3.2.3 EFI_FFS_FILE_HEADER
	sum := Checksum8(f.buf[:headerSize])
	sum -= fh.Checksum.File
	sum -= fh.State
	if sum != 0 {
		errs = append(errs, fmt.Errorf("file %v header checksum failure! sum was %v",
			fh.Name, sum))
	}

	// Body Checksum
	if !fh.Attributes.hasChecksum() && fh.Checksum.File != emptyBodyChecksum {
		errs = append(errs, fmt.Errorf("file %v body checksum failure! Attribute was not set, but sum was %v instead of %v",
			fh.Name, sum, emptyBodyChecksum))
	} else if fh.Attributes.hasChecksum() {
		sum = Checksum8(f.buf[headerSize:])
		if sum != 0 {
			errs = append(errs, fmt.Errorf("file %v body checksum failure! sum was %v",
				fh.Name, sum))
		}
	}

	for _, s := range f.Sections {
		errs = append(errs, s.Validate()...)
	}
	return errs
}

// NewFirmwareFile parses a sequence of bytes and returns a FirmwareFile
// object, if a valid one is passed, or an error. If no error is returned and the FirmwareFile
// pointer is nil, it means we've reached the volume free space at the end of the FV.
func NewFirmwareFile(buf []byte) (*FirmwareFile, error) {
	f := FirmwareFile{}
	f.DataOffset = FileHeaderMinLength
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
		f.DataOffset = FileHeaderExtMinLength
	} else {
		// Copy small size into big for easier handling.
		// Damn the 3 byte sizes.
		f.Header.ExtendedSize = Read3Size(f.Header.Size)
	}

	if buflen := len(buf); f.Header.ExtendedSize > uint64(buflen) {
		return nil, fmt.Errorf("File size too big! File with GUID: %v has length %v, but is only %v bytes big",
			f.Header.Name, f.Header.ExtendedSize, buflen)
	}
	// Slice buffer to the correct size.
	f.buf = buf[:f.Header.ExtendedSize]

	// Parse sections
	switch f.Header.Type {
	case fvFileTypeRaw:
		fallthrough
	case fvFileTypePad:
		// We don't handle sections for all of the above
		return &f, nil
	}
	for offset := f.DataOffset; offset < f.Header.ExtendedSize; {
		s, err := NewFileSection(f.buf[offset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing sections of file %v: %v", f.Header.Name, err)
		}
		offset += uint64(s.Header.ExtendedSize)
		// Align to 4 bytes for now. The PI Spec doesn't say what alignment it should be
		// but UEFITool aligns to 4 bytes, and this seems to work on everything I have.
		offset = Align4(offset)
		f.Sections = append(f.Sections, s)
	}

	return &f, nil
}
