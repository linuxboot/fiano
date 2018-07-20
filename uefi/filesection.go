package uefi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
)

const (
	// SectionMinLength is the minimum length of a file section header.
	SectionMinLength = 0x08
)

// SectionType holds a section type value
type SectionType uint8

// FileSectionHeader represents an EFI_COMMON_SECTION_HEADER as specified in
// UEFI PI Spec 3.2.4 Firmware File Section
type FileSectionHeader struct {
	Size [3]uint8
	Type SectionType
}

// FileSectionExtHeader represents an EFI_COMMON_SECTION_HEADER2 as specified in
// UEFI PI Spec 3.2.4 Firmware File Section
type FileSectionExtHeader struct {
	FileSectionHeader
	ExtendedSize uint32
}

// FileSection represents a Firmware File Section
type FileSection struct {
	Header FileSectionExtHeader
	buf    []byte

	//Metadata for extraction and recovery
	ExtractPath string
	fileOrder   int
}

// Assemble assembles the section from the binary
func (f *FileSection) Assemble() ([]byte, error) {
	var err error
	f.buf, err = ioutil.ReadFile(f.ExtractPath)
	if err != nil {
		return nil, err
	}
	return f.buf, nil
}

// Extract extracts the Section to the directory passed in.
func (f *FileSection) Extract(parentPath string) error {
	// Dump the binary
	var err error
	// For sections we just extract to the parentpath
	f.ExtractPath, err = ExtractBinary(f.buf, parentPath, fmt.Sprintf("%v.sec", f.fileOrder))
	return err
}

// Validate File Section
func (f *FileSection) Validate() []error {
	errs := make([]error, 0)
	buflen := uint32(len(f.buf))
	blankSize := [3]uint8{0xFF, 0xFF, 0xFF}

	// Size Checks
	fh := &f.Header
	if fh.Size == blankSize {
		if buflen < SectionMinLength {
			errs = append(errs, fmt.Errorf("section length too small!, buffer is only %#x bytes long for extended header",
				buflen))
			return errs
		}
	} else if uint32(Read3Size(f.Header.Size)) != fh.ExtendedSize {
		errs = append(errs, errors.New("section size not copied into extendedsize"))
		return errs
	}
	if buflen != fh.ExtendedSize {
		errs = append(errs, fmt.Errorf("section size mismatch! Size is %#x, buf length is %#x",
			fh.ExtendedSize, buflen))
		return errs
	}

	return errs
}

// NewFileSection parses a sequence of bytes and returns a FirmwareFile
// object, if a valid one is passed, or an error. If no error is returned and the FirmwareFile
// pointer is nil, it means we've reached the volume free space at the end of the FV.
func NewFileSection(buf []byte, fileOrder int) (*FileSection, error) {
	f := FileSection{fileOrder: fileOrder}
	// Read in standard header.
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &f.Header.FileSectionHeader); err != nil {
		return nil, err
	}

	if f.Header.Size == [3]uint8{0xFF, 0xFF, 0xFF} {
		// Extended Header
		if err := binary.Read(r, binary.LittleEndian, &f.Header.ExtendedSize); err != nil {
			return nil, err
		}
		if f.Header.ExtendedSize == 0xFFFFFFFF {
			return nil, errors.New("section size and extended size are all FFs! there should not be free space inside a file")
		}
	} else {
		// Copy small size into big for easier handling.
		// Section's extended size is 32 bits unlike file's
		f.Header.ExtendedSize = uint32(Read3Size(f.Header.Size))
	}

	if buflen := len(buf); int(f.Header.ExtendedSize) > buflen {
		return nil, fmt.Errorf("section size too big! Section has length %v, but is only %v bytes big",
			f.Header.ExtendedSize, buflen)
	}
	// Slice buffer to the correct size.
	f.buf = buf[:f.Header.ExtendedSize]

	return &f, nil
}
