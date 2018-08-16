package uefi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"
	"unsafe"

	"github.com/linuxboot/fiano/pkg/lzma"
	"github.com/linuxboot/fiano/unicode"
	"github.com/linuxboot/fiano/uuid"
)

const (
	// SectionMinLength is the minimum length of a file section header.
	SectionMinLength = 0x08
)

// SectionType holds a section type value
type SectionType uint8

// UEFI Section types
const (
	SectionTypeAll                 SectionType = 0x00
	SectionTypeCompression         SectionType = 0x01
	SectionTypeGUIDDefined         SectionType = 0x02
	SectionTypeDisposable          SectionType = 0x03
	SectionTypePE32                SectionType = 0x10
	SectionTypePIC                 SectionType = 0x11
	SectionTypeTE                  SectionType = 0x12
	SectionTypeDXEDepEx            SectionType = 0x13
	SectionTypeVersion             SectionType = 0x14
	SectionTypeUserInterface       SectionType = 0x15
	SectionTypeCompatibility16     SectionType = 0x16
	SectionTypeFirmwareVolumeImage SectionType = 0x17
	SectionTypeFreeformSubtypeGUID SectionType = 0x18
	SectionTypeRaw                 SectionType = 0x19
	SectionTypePEIDepEx            SectionType = 0x1b
	SectionMMDepEx                 SectionType = 0x1c
)

var sectionNames = map[SectionType]string{
	SectionTypeCompression:         "EFI_SECTION_COMPRESSION",
	SectionTypeGUIDDefined:         "EFI_SECTION_GUID_DEFINED",
	SectionTypeDisposable:          "EFI_SECTION_DISPOSABLE",
	SectionTypePE32:                "EFI_SECTION_PE32",
	SectionTypePIC:                 "EFI_SECTION_PIC",
	SectionTypeTE:                  "EFI_SECTION_TE",
	SectionTypeDXEDepEx:            "EFI_SECTION_DXE_DEPEX",
	SectionTypeVersion:             "EFI_SECTION_VERSION",
	SectionTypeUserInterface:       "EFI_SECTION_USER_INTERFACE",
	SectionTypeCompatibility16:     "EFI_SECTION_COMPATIBILITY16",
	SectionTypeFirmwareVolumeImage: "EFI_SECTION_FIRMWARE_VOLUME_IMAGE",
	SectionTypeFreeformSubtypeGUID: "EFI_SECTION_FREEFORM_SUBTYPE_GUID",
	SectionTypeRaw:                 "EFI_SECTION_RAW",
	SectionTypePEIDepEx:            "EFI_SECTION_PEI_DEPEX",
	SectionMMDepEx:                 "EFI_SECTION_MM_DEPEX",
}

// GUIDEDSectionAttribute holds a GUIDED section attribute bitfield
type GUIDEDSectionAttribute uint16

// UEFI GUIDED Section Attributes
const (
	GUIDEDSectionProcessingRequired GUIDEDSectionAttribute = 0x01
	GUIDEDSectionAuthStatusValid    GUIDEDSectionAttribute = 0x02
)

var lzmaGUID = *uuid.MustParse("EE4E5898-3914-4259-9D6E-DC7BD79403CF")

// SectionHeader represents an EFI_COMMON_SECTION_HEADER as specified in
// UEFI PI Spec 3.2.4 Firmware File Section
type SectionHeader struct {
	Size [3]uint8 `json:"-"`
	Type SectionType
}

// SectionExtHeader represents an EFI_COMMON_SECTION_HEADER2 as specified in
// UEFI PI Spec 3.2.4 Firmware File Section
type SectionExtHeader struct {
	SectionHeader
	ExtendedSize uint32 `json:"-"`
}

// SectionGUIDDefinedHeader contains the fields for a EFI_SECTION_GUID_DEFINED
// encapsulated section header.
type SectionGUIDDefinedHeader struct {
	GUID       uuid.UUID
	DataOffset uint16
	Attributes uint16
}

// SectionGUIDDefined contains the type specific fields for a
// EFI_SECTION_GUID_DEFINED section.
type SectionGUIDDefined struct {
	SectionGUIDDefinedHeader
	Compression string
}

// Section represents a Firmware File Section
type Section struct {
	Header SectionExtHeader
	Type   string
	buf    []byte

	// Metadata for extraction and recovery
	ExtractPath string
	fileOrder   int

	// Type specific fields
	TypeSpecific interface{} `json:",omitempty"`

	// For EFI_SECTION_USER_INTERFACE
	Name string `json:",omitempty"`

	// Encapsulated firmware
	Encapsulated []*TypedFirmware `json:",omitempty"`
}

// Assemble assembles the section from the binary
func (s *Section) Assemble() ([]byte, error) {
	var err error
	s.buf, err = ioutil.ReadFile(s.ExtractPath)
	if err != nil {
		return nil, err
	}
	return s.buf, nil
}

// Extract extracts the Section to the directory passed in.
func (s *Section) Extract(parentPath string) error {
	// Dump the binary
	var err error
	// For sections we just extract to the parentpath
	s.ExtractPath, err = ExtractBinary(s.buf, parentPath, fmt.Sprintf("%v.sec", s.fileOrder))
	return err
}

// Validate File Section
func (s *Section) Validate() []error {
	errs := make([]error, 0)
	buflen := uint32(len(s.buf))
	blankSize := [3]uint8{0xFF, 0xFF, 0xFF}

	// Size Checks
	sh := &s.Header
	if sh.Size == blankSize {
		if buflen < SectionMinLength {
			errs = append(errs, fmt.Errorf("section length too small!, buffer is only %#x bytes long for extended header",
				buflen))
			return errs
		}
	} else if uint32(Read3Size(s.Header.Size)) != sh.ExtendedSize {
		errs = append(errs, errors.New("section size not copied into extendedsize"))
		return errs
	}
	if buflen != sh.ExtendedSize {
		errs = append(errs, fmt.Errorf("section size mismatch! Size is %#x, buf length is %#x",
			sh.ExtendedSize, buflen))
		return errs
	}

	return errs
}

// NewSection parses a sequence of bytes and returns a Section
// object, if a valid one is passed, or an error.
func NewSection(buf []byte, fileOrder int) (*Section, error) {
	s := Section{fileOrder: fileOrder}
	// Read in standard header.
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &s.Header.SectionHeader); err != nil {
		return nil, err
	}

	// Map type to string
	if t, ok := sectionNames[s.Header.Type]; ok {
		s.Type = t
	}

	headerSize := unsafe.Sizeof(SectionHeader{})
	if s.Header.Size == [3]uint8{0xFF, 0xFF, 0xFF} {
		// Extended Header
		if err := binary.Read(r, binary.LittleEndian, &s.Header.ExtendedSize); err != nil {
			return nil, err
		}
		if s.Header.ExtendedSize == 0xFFFFFFFF {
			return nil, errors.New("section size and extended size are all FFs! there should not be free space inside a file")
		}
		headerSize = unsafe.Sizeof(SectionExtHeader{})
	} else {
		// Copy small size into big for easier handling.
		// Section's extended size is 32 bits unlike file's
		s.Header.ExtendedSize = uint32(Read3Size(s.Header.Size))
	}

	if buflen := len(buf); int(s.Header.ExtendedSize) > buflen {
		return nil, fmt.Errorf("section size mismatch! Section has size %v, but buffer is %v bytes big",
			s.Header.ExtendedSize, buflen)
	}
	// Slice buffer to the correct size.
	s.buf = buf[:s.Header.ExtendedSize]

	// Section type specific data
	switch s.Header.Type {
	case SectionTypeGUIDDefined:
		typeSpec := &SectionGUIDDefined{}
		if err := binary.Read(r, binary.LittleEndian, &typeSpec.SectionGUIDDefinedHeader); err != nil {
			return nil, err
		}
		s.TypeSpecific = typeSpec

		// Determine how to interpret the section based on the GUID.
		var encapBuf []byte
		if typeSpec.Attributes&uint16(GUIDEDSectionProcessingRequired) != 0 {
			switch typeSpec.GUID {
			case lzmaGUID:
				var err error
				encapBuf, err = lzma.Decode(buf[typeSpec.DataOffset:])
				if err != nil {
					encapBuf = []byte{}
					typeSpec.Compression = "UNKNOWN"
				} else {
					typeSpec.Compression = "LZMA"
				}
			default:
				typeSpec.Compression = "UNKNOWN"
			}
		}

		for i, offset := 0, uint64(0); offset < uint64(len(encapBuf)); i++ {
			encapS, err := NewSection(encapBuf[offset:], i)
			if err != nil {
				return nil, fmt.Errorf("error parsing encapsulated section #%d at offset %d",
					i, offset)
			}
			// Align to 4 bytes for now. The PI Spec doesn't say what alignment it should be
			// but UEFITool aligns to 4 bytes, and this seems to work on everything I have.
			offset = Align4(offset + uint64(encapS.Header.ExtendedSize))
			s.Encapsulated = append(s.Encapsulated, &TypedFirmware{
				Type:  reflect.TypeOf(encapS).String(),
				Value: encapS,
			})
		}

	case SectionTypeUserInterface:
		s.Name = unicode.UCS2ToUTF8(s.buf[headerSize:])
	}

	return &s, nil
}
