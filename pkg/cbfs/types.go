// Copyright 2018-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbfs

import (
	"encoding/binary"
	"io"

	"github.com/linuxboot/fiano/pkg/fmap"
)

type Props struct {
	Offset uint32
	Size   uint32
}

type Compression uint32

const (
	None Compression = iota
	LZMA
	LZ4
)

var Endian = binary.BigEndian

// These are standard component types for well known
//   components (i.e - those that coreboot needs to consume.
//   Users are welcome to use any other value for their
//   components.
type FileType uint32

const (
	// FOV
	TypeDeleted2    FileType = 0xffffffff
	TypeDeleted     FileType = 0
	TypeBootBlock   FileType = 0x1
	TypeMaster      FileType = 0x2
	TypeLegacyStage FileType = 0x10
	TypeStage       FileType = 0x11
	TypeSELF        FileType = 0x20
	TypeFIT         FileType = 0x21
	TypeOptionRom   FileType = 0x30
	TypeBootSplash  FileType = 0x40
	TypeRaw         FileType = 0x50
	TypeVSA         FileType = 0x51 // very, very obsolete Geode thing
	TypeMBI         FileType = 0x52
	TypeMicroCode   FileType = 0x53
	TypeFSP         FileType = 0x60
	TypeMRC         FileType = 0x61
	TypeMMA         FileType = 0x62
	TypeEFI         FileType = 0x63
	TypeStruct      FileType = 0x70
	TypeCMOS        FileType = 0xaa
	TypeSPD         FileType = 0xab
	TypeMRCCache    FileType = 0xac
	TypeCMOSLayout  FileType = 0x1aa
)

const (
	HeaderMagic   = 0x4F524243
	HeaderV1      = 0x31313131
	HeaderV2      = 0x31313132
	HeaderVersion = HeaderV2
	Alignment     = 64
)

/** This is a component header - every entry in the CBFS
  will have this header.

  This is how the component is arranged in the ROM:

  --------------   <- 0
  component header
  --------------   <- sizeof(struct component)
  component name
  --------------   <- offset
  data
  ...
  --------------   <- offset + len
*/

const FileMagic = "LARCHIVE"

const FileSize = 24

type FileHeader struct {
	Magic           [8]byte
	Size            uint32
	Type            FileType
	AttrOffset      uint32
	SubHeaderOffset uint32
}

type File struct {
	FileHeader
	RecordStart uint32
	Name        string
	Attr        []byte
	FData       []byte
}

type mFile struct {
	Name        string
	Start       uint32
	Size        uint32
	Type        string
	Compression string
}

// The common fields of extended cbfs file attributes.
// Attributes are expected to start with tag/len, then append their
// specific fields.
type FileAttr struct {
	Tag  uint32
	Size uint32 // inclusize of Tag and Size
}

type Tag uint32

const (
	Unused     Tag = 0
	Unused2    Tag = 0xffffffff
	Compressed Tag = 0x42435a4c
	Hash       Tag = 0x68736148
	PSCB       Tag = 0x42435350
	ALCB       Tag = 0x42434c41
	SHCB       Tag = 0x53746748
)

type FileAttrCompression struct {
	Tag              Tag
	Size             uint32
	Compression      Compression
	DecompressedSize uint32
}

type FileAttrHash struct {
	Tag      Tag
	Size     uint32 // includes everything including data.
	HashType uint32
	Data     []byte
}

type FileAttrPos struct {
	Tag  Tag
	Size uint32 // includes everything including data.
	Pos  uint32
}

type FileAttrAlign struct {
	Tag   Tag
	Size  uint32 // includes everything including data.
	Align uint32
}

type FileAttrStageHeader struct {
	Tag         Tag
	Size        uint32
	LoadAddress uint64
	EntryOffset uint32
	MemSize     uint32
}

// Component sub-headers

// Following are component sub-headers for the "standard"
// component types

// this is the master cbfs header - it must be located somewhere available
// to bootblock (to load romstage). The last 4 bytes in the image contain its
// relative offset from the end of the image (as a 32-bit signed integer).
const MasterHeaderLen = 32

type MasterHeader struct {
	Magic         uint32
	Version       uint32
	RomSize       uint32
	BootBlockSize uint32
	Align         uint32 // always 64 bytes -- FOV
	Offset        uint32
	Architecture  Architecture // integer, not name -- FOV
	_             uint32
}

type MasterRecord struct {
	File
	MasterHeader
}

type Architecture uint32

const (
	X86 Architecture = 1
	ARM Architecture = 0x10
)

type StageHeader struct {
	Compression Compression
	Entry       uint64
	LoadAddress uint64
	Size        uint32
	MemSize     uint32
}

type LegacyStageRecord struct {
	File
	StageHeader
	Data []byte
}

type StageRecord struct {
	File
	FileAttrStageHeader
	Data []byte
}

type UnknownRecord struct {
	File
}

type RawRecord struct {
	File
}

type EmptyRecord struct {
	File
}

type CMOSRecord struct {
	File
}

type CMOSLayoutRecord struct {
	File
}

type MicrocodeRecord struct {
	File
}

type OptionROMRecord struct {
	File
}

type BootBlockRecord struct {
	File
}

type BootSplashRecord struct {
	File
}

type SPDRecord struct {
	File
}

type FSPRecord struct {
	File
}

type PayloadHeader struct {
	Type        SegmentType
	Compression Compression
	Offset      uint32
	LoadAddress uint64
	Size        uint32
	MemSize     uint32
}

type PayloadRecord struct {
	File
	Segs []PayloadHeader
	Data []byte
}

// fix this mess later to use characters, not constants.
// I had done this once and it never made it into coreboot
// and I still don't know why.
type SegmentType uint32

const (
	SegCode   SegmentType = 0x434F4445
	SegData   SegmentType = 0x44415441
	SegBSS    SegmentType = 0x42535320
	SegParams SegmentType = 0x50415241
	SegEntry  SegmentType = 0x454E5452
)

func (s SegmentType) String() string {
	switch s {
	case SegCode:
		return "code"
	case SegData:
		return "data"
	case SegBSS:
		return "bss"
	case SegParams:
		return "params"
	case SegEntry:
		return "entry"
	}
	return "unknown"
}

type OptionRom struct {
	File
	Compression Compression
	Size        uint32
}

// Each CBFS file type must implement at least this interface.
type ReadWriter interface {
	GetFile() *File
	String() string
	Read(r io.ReadSeeker) error
	Write(f io.Writer) error
}

type Image struct {
	Segs []ReadWriter
	// Scarf away the fmap info.
	FMAP         *fmap.FMap
	FMAPMetadata *fmap.Metadata
	Area         *fmap.Area
	// And all the data.
	Data []byte
}
