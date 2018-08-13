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

var supportedFiles = map[FVFileType]bool{
	// These are the file types that we'll actually try to parse sections for.
	fvFileTypeFreeForm:           true,
	fvFileTypeSECCore:            true,
	fvFileTypePEICore:            true,
	fvFileTypeDXECore:            true,
	fvFileTypePEIM:               true,
	fvFileTypeDriver:             true,
	fvFileTypeCombinedPEIMDriver: true,
	fvFileTypeApplication:        true,
	fvFileTypeSMM:                true,
	fvFileTypeVolumeImage:        true,
	fvFileTypeCombinedSMMDXE:     true,
	fvFileTypeSMMCore:            true,
	fvFileTypeSMMStandalone:      true,
	fvFileTypeSMMCoreStandalone:  true,
}

// Stock GUIDS
var (
	ZeroGUID *uuid.UUID
	FFGUID   *uuid.UUID
)

func init() {
	ZeroGUID, _ = uuid.Parse("00000000-0000-0000-0000-000000000000")
	FFGUID, _ = uuid.Parse("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
}

// FileAlignments specifies the correct alignments based on the field in the file header.
var fileAlignments = []uint64{
	// These alignments not computable, we have to look them up.
	1,
	16,
	128,
	512,
	1024,
	4 * 1024,
	32 * 1024,
	64 * 1024,
	128 * 1024,
	256 * 1024,
	512 * 1024,
	1024 * 1024,
	2 * 1024 * 1024,
	4 * 1024 * 1024,
	8 * 1024 * 1024,
	16 * 1024 * 1024,
}

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
	UUID       uuid.UUID      // This is the GUID of the file.
	Checksum   IntegrityCheck `json:"-"`
	Type       FVFileType
	Attributes fileAttr
	Size       [3]uint8 `json:"-"`
	State      uint8    `json:"-"`
}

// Checks if the large file attribute is set
func (a fileAttr) isLarge() bool {
	return a&0x01 != 0
}

// GetAlignment returns the byte alignment specified by the file header.
func (a fileAttr) GetAlignment() uint64 {
	alignVal := (a & 0x38) >> 3
	alignVal |= (a & 0x02) << 2
	return fileAlignments[alignVal]
}

// Sets the large file attribute.
func (a *fileAttr) setLarge(large bool) {
	if large {
		*a |= 0x01
	} else {
		*a &= 0xFE
	}
}

// Checks if we need to checksum the file body
func (a fileAttr) hasChecksum() bool {
	return a&0x40 != 0
}

// HeaderLen is a helper function to return the length of the file header
// depending on the file size
func (f *FirmwareFile) HeaderLen() uint64 {
	if f.Header.Attributes.isLarge() {
		return FileHeaderExtMinLength
	}
	return FileHeaderMinLength
}

func (f *FirmwareFile) checksumHeader() uint8 {
	fh := f.Header
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
	return sum
}

// FirmwareFileHeaderExtended represents an EFI File header with the
// large file attribute set.
// We also use this as the generic header for all EFI files, regardless of whether
// they are actually large. This makes it easier for us to just return one type
// All sizes are also copied into the ExtendedSize field so we only have to check once
type FirmwareFileHeaderExtended struct {
	FirmwareFileHeader
	ExtendedSize uint64 `json:"-"`
}

// FirmwareFile represents an EFI File.
type FirmwareFile struct {
	Header   FirmwareFileHeaderExtended
	Sections []*Section `json:",omitempty"`

	//Metadata for extraction and recovery
	buf         []byte
	ExtractPath string
	DataOffset  uint64
}

func (f *FirmwareFile) setSize(size uint64, resizeFile bool) {
	fh := &f.Header
	// See if we need the extended size
	// Check if size > 3 bytes size field
	fh.ExtendedSize = size
	fh.Attributes.setLarge(false)
	if fh.ExtendedSize > 0xFFFFFF {
		// Can't fit, need extended header
		if resizeFile {
			// Increase the file size by the additional space needed
			// for the extended header.
			fh.ExtendedSize += FileHeaderExtMinLength - FileHeaderMinLength
		}
		fh.Attributes.setLarge(true)
	}
	// This will set size to 0xFFFFFF if too big.
	fh.Size = Write3Size(fh.ExtendedSize)
}

func (f *FirmwareFile) checksumAndAssemble(fileData []byte) error {
	// Checksum the header and body, then write out the header.
	// To checksum the header we write the temporary header to the file buffer first.
	fh := &f.Header

	header := new(bytes.Buffer)
	err := binary.Write(header, binary.LittleEndian, fh)
	if err != nil {
		return fmt.Errorf("unable to construct binary header of file %v, got %v",
			fh.UUID, err)
	}
	f.buf = header.Bytes()
	// We need to get rid of whatever it sums to so that the overall sum is zero
	// Sorry about the name :(
	fh.Checksum.Header -= f.checksumHeader()

	// Checksum the body
	fh.Checksum.File = emptyBodyChecksum
	if fh.Attributes.hasChecksum() {
		// if the empty checksum had been set to 0 instead of 0xAA
		// this could have been a bit nicer. BUT NOOOOOOO.
		fh.Checksum.File = 0 - Checksum8(fileData)
	}

	// Write out the updated header to the buffer with the new checksums.
	// Write the extended header only if the large attribute flag is set.
	header = new(bytes.Buffer)
	if fh.Attributes.isLarge() {
		err = binary.Write(header, binary.LittleEndian, fh)
	} else {
		err = binary.Write(header, binary.LittleEndian, fh.FirmwareFileHeader)
	}
	if err != nil {
		return err
	}
	f.buf = header.Bytes()

	f.buf = append(f.buf, fileData...)
	return nil
}

// Assemble assembles the Firmware File
func (f *FirmwareFile) Assemble() ([]byte, error) {
	var err error

	fh := &f.Header
	if _, ok := supportedFiles[fh.Type]; !ok || len(f.Sections) == 0 {
		// we don't support this file type, just return the raw buffer.
		// Or we've removed the sections and just want to replace the file directly
		// We have to make sure the state is correct, so we still need to write out
		// the file header.

		// Set state to valid based on erase polarity
		// We really should redo the whole header
		// TODO: Reconstruct header from JSON
		fh.State = 0x07 ^ Attributes.ErasePolarity
		f.buf, err = ioutil.ReadFile(f.ExtractPath)
		if err != nil {
			return nil, err
		}
		f.buf[0x17] = fh.State
		return f.buf, nil
	}

	// Otherwise, we reconstruct the entire file from the sections and the
	// file header using data from the JSON. This means that some JSON values
	// are now respected, including GUID changes. However file lengths and
	// checksums will be recalculated.

	// Assemble all sections so we know the final file size. We need to do this
	// to know if we need to use the extended header.
	fileData := []byte{}
	dLen := uint64(0)
	for _, s := range f.Sections {
		// Align to 4 bytes and extend with 00s
		// Why is it 00s? I don't know. Everything else has been extended with FFs
		// but somehow in between sections alignment is done with 0s. What the heck.
		for count := Align4(dLen) - dLen; count > 0; count-- {
			fileData = append(fileData, 0x00)
		}
		dLen = Align4(dLen)

		// Assemble the section and append
		sData, err := s.Assemble()
		if err != nil {
			return nil, err
		}
		dLen += uint64(len(sData))
		fileData = append(fileData, sData...)
	}

	f.setSize(FileHeaderMinLength+dLen, true)

	// Set state to valid based on erase polarity
	fh.State = 0x07 ^ Attributes.ErasePolarity

	if err = f.checksumAndAssemble(fileData); err != nil {
		return nil, err
	}
	return f.buf, nil
}

// Extract extracts the FFS to the directory passed in.
func (f *FirmwareFile) Extract(parentPath string) error {
	// Dump the binary
	var err error
	// For files we use the GUID as the folder name.
	dirPath := filepath.Join(parentPath, f.Header.UUID.String())
	f.ExtractPath, err = ExtractBinary(f.buf, dirPath, fmt.Sprintf("%v.ffs", f.Header.UUID))
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
	blankSize := [3]uint8{0xFF, 0xFF, 0xFF}
	if buflen < FileHeaderMinLength {
		errs = append(errs, fmt.Errorf("file length too small!, buffer is only %#x bytes long", buflen))
		return errs
	}

	// Size Checks
	fh := &f.Header
	if fh.Size == blankSize {
		if buflen < FileHeaderExtMinLength {
			errs = append(errs, fmt.Errorf("file %v length too small!, buffer is only %#x bytes long for extended header",
				fh.UUID, buflen))
			return errs
		}
		if !fh.Attributes.isLarge() {
			errs = append(errs, fmt.Errorf("file %v using extended header, but large attribute is not set",
				fh.UUID))
			return errs
		}
	} else if Read3Size(f.Header.Size) != fh.ExtendedSize {
		errs = append(errs, fmt.Errorf("file %v size not copied into extendedsize",
			fh.UUID))
		return errs
	}
	if buflen != fh.ExtendedSize {
		errs = append(errs, fmt.Errorf("file %v size mismatch! Size is %#x, buf length is %#x",
			fh.UUID, fh.ExtendedSize, buflen))
		return errs
	}

	// Header Checksums
	if sum := f.checksumHeader(); sum != 0 {
		errs = append(errs, fmt.Errorf("file %v header checksum failure! sum was %v",
			fh.UUID, sum))
	}

	// Body Checksum
	if !fh.Attributes.hasChecksum() && fh.Checksum.File != emptyBodyChecksum {
		errs = append(errs, fmt.Errorf("file %v body checksum failure! Attribute was not set, but sum was %v instead of %v",
			fh.UUID, fh.Checksum.File, emptyBodyChecksum))
	} else if fh.Attributes.hasChecksum() {
		headerSize := FileHeaderMinLength
		if fh.Attributes.isLarge() {
			headerSize = FileHeaderExtMinLength
		}
		if sum := Checksum8(f.buf[headerSize:]); sum != 0 {
			errs = append(errs, fmt.Errorf("file %v body checksum failure! sum was %v",
				fh.UUID, sum))
		}
	}

	for _, s := range f.Sections {
		errs = append(errs, s.Validate()...)
	}
	return errs
}

// CreatePadFile creates an empty pad file in order to align the next file.
func CreatePadFile(size uint64) (*FirmwareFile, error) {
	if size < FileHeaderMinLength {
		return nil, fmt.Errorf("size too small! min size required is %#x bytes, requested %#x",
			FileHeaderMinLength, size)
	}

	f := FirmwareFile{}
	fh := &f.Header

	// Create empty guid
	if Attributes.ErasePolarity == 0xFF {
		fh.UUID = *FFGUID
	} else if Attributes.ErasePolarity == 0 {
		fh.UUID = *ZeroGUID
	} else {
		return nil, fmt.Errorf("erase polarity not 0x00 or 0xFF, got %#x", Attributes.ErasePolarity)
	}

	// TODO: I see examples of this where the attributes are just 0 and not dependent on the
	// erase polarity. Is that right? Check and handle.
	fh.Attributes = 0

	// Set the size. If the file is too big, we take up more of the padding for the header.
	// This also sets the large file attribute if file is big.
	f.setSize(size, false)
	fh.Type = fvFileTypePad

	// Create empty pad filedata based on size
	var fileData []byte
	fileData = make([]byte, size-FileHeaderMinLength)
	if fh.Attributes.isLarge() {
		fileData = make([]byte, size-FileHeaderExtMinLength)
	}
	// Fill with empty bytes
	for i, dataLen := 0, len(fileData); i < dataLen; i++ {
		fileData[i] = Attributes.ErasePolarity
	}

	fh.State = 0x07 ^ Attributes.ErasePolarity

	// Everything has been setup. Checksum and create.
	if err := f.checksumAndAssemble(fileData); err != nil {
		return nil, err
	}
	return &f, nil
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
	if f.Header.Size == [3]uint8{0xFF, 0xFF, 0xFF} {
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
			f.Header.UUID, f.Header.ExtendedSize, buflen)
	}
	// Slice buffer to the correct size.
	f.buf = buf[:f.Header.ExtendedSize]

	// Parse sections
	if _, ok := supportedFiles[f.Header.Type]; !ok {
		return &f, nil
	}
	for i, offset := 0, f.DataOffset; offset < f.Header.ExtendedSize; i++ {
		s, err := NewSection(f.buf[offset:], i)
		if err != nil {
			return nil, fmt.Errorf("error parsing sections of file %v: %v", f.Header.UUID, err)
		}
		offset += uint64(s.Header.ExtendedSize)
		// Align to 4 bytes for now. The PI Spec doesn't say what alignment it should be
		// but UEFITool aligns to 4 bytes, and this seems to work on everything I have.
		offset = Align4(offset)
		f.Sections = append(f.Sections, s)
	}

	return &f, nil
}
