package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	uuid "github.com/linuxboot/fiano/uuid"
)

// FirmwareVolume constants
const (
	FirmwareVolumeFixedHeaderSize  = 56
	FirmwareVolumeMinSize          = FirmwareVolumeFixedHeaderSize + 8 // +8 for the null block that terminates the block list
	FirmwareVolumeExtHeaderMinSize = 20
)

// FVGUIDs holds common FV type names
var FVGUIDs map[uuid.UUID]string

// Valid FV GUIDs
var (
	FFS1      *uuid.UUID
	FFS2      *uuid.UUID
	FFS3      *uuid.UUID
	EVSA      *uuid.UUID
	NVAR      *uuid.UUID
	EVSA2     *uuid.UUID
	AppleBoot *uuid.UUID
	PFH1      *uuid.UUID
	PFH2      *uuid.UUID
)

func init() {
	FFS1, _ = uuid.Parse("7a9354d9-0468-444a-81ce-0bf617d890df")
	FFS2, _ = uuid.Parse("8c8ce578-8a3d-4f1c-9935-896185c32dd3")
	FFS3, _ = uuid.Parse("5473c07a-3dcb-4dca-bd6f-1e9689e7349a")
	EVSA, _ = uuid.Parse("fff12b8d-7696-4c8b-a985-2747075b4f50")
	NVAR, _ = uuid.Parse("cef5b9a3-476d-497f-9fdc-e98143e0422c")
	EVSA2, _ = uuid.Parse("00504624-8a59-4eeb-bd0f-6b36e96128e0")
	AppleBoot, _ = uuid.Parse("04adeead-61ff-4d31-b6ba-64f8bf901f5a")
	PFH1, _ = uuid.Parse("16b45da2-7d70-4aea-a58d-760e9ecb841d")
	PFH2, _ = uuid.Parse("e360bdba-c3ce-46be-8f37-b231e5cb9f35")

	// Add names to map
	FVGUIDs = make(map[uuid.UUID]string)
	FVGUIDs[*FFS1] = "FFS1"
	FVGUIDs[*FFS2] = "FFS2"
	FVGUIDs[*FFS3] = "FFS3"
	FVGUIDs[*EVSA] = "NVRAM_EVSA"
	FVGUIDs[*NVAR] = "NVRAM_NVAR"
	FVGUIDs[*EVSA2] = "NVRAM_EVSA2"
	FVGUIDs[*AppleBoot] = "APPLE_BOOT"
	FVGUIDs[*PFH1] = "PFH1"
	FVGUIDs[*PFH2] = "PFH2"
}

// Block describes number and size of the firmware volume blocks
type Block struct {
	Count uint32
	Size  uint32
}

// FirmwareVolumeFixedHeader contains the fixed fields of a firmware volume
// header
type FirmwareVolumeFixedHeader struct {
	_               [16]uint8
	FileSystemGUID  uuid.UUID
	Length          uint64
	Signature       uint32
	Attributes      uint32 // UEFI PI spec volume 3.2.1 EFI_FIRMWARE_VOLUME_HEADER
	HeaderLen       uint16
	Checksum        uint16
	ExtHeaderOffset uint16
	Reserved        uint8 `json:"-"`
	Revision        uint8
	// _               [3]uint8
}

// FirmwareVolumeExtHeader contains the fields of an extended firmware volume
// header
type FirmwareVolumeExtHeader struct {
	FVName        uuid.UUID
	ExtHeaderSize uint32
}

// FirmwareVolume represents a firmware volume. It combines the fixed header and
// a variable list of blocks
type FirmwareVolume struct {
	FirmwareVolumeFixedHeader
	// there must be at least one that is zeroed and indicates the end of the
	// block list
	// We don't really have to care about blocks because we just read everything in.
	Blocks []Block
	FirmwareVolumeExtHeader
	Files []FirmwareFile

	// Variables not in the binary for us to keep track of stuff/print
	DataOffset uint64
	fvType     string
	buf        []byte
}

// FindFirmwareVolumeOffset searches for a firmware volume signature, "_FVH"
// using 8-byte alignment. If found, returns the offset from the start of the
// bios region, otherwise returns -1.
func FindFirmwareVolumeOffset(data []byte) int64 {
	if len(data) < 32 {
		return -1
	}
	var (
		offset int64
		fvSig  = []byte("_FVH")
	)
	for offset = 32; offset < int64(len(data)); offset += 8 {
		if bytes.Equal(data[offset:offset+4], fvSig) {
			return offset - 40 // the actual volume starts 40 bytes before the signature
		}
	}
	return -1
}

func align8(val uint64) uint64 {
	return (val + 7) & ^uint64(7)
}

// NewFirmwareVolume parses a sequence of bytes and returns a FirmwareVolume
// object, if a valid one is passed, or an error
func NewFirmwareVolume(data []byte) (*FirmwareVolume, error) {
	var fv FirmwareVolume

	if len(data) < FirmwareVolumeMinSize {
		return nil, fmt.Errorf("Firmware Volume size too small: expected %v bytes, got %v",
			FirmwareVolumeMinSize,
			len(data),
		)
	}
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &fv.FirmwareVolumeFixedHeader); err != nil {
		return nil, err
	}
	// read the block map
	blocks := make([]Block, 0)
	for {
		var block Block
		if err := binary.Read(reader, binary.LittleEndian, &block); err != nil {
			return nil, err
		}
		if block.Count == 0 && block.Size == 0 {
			// found the terminating block
			break
		}
		blocks = append(blocks, block)
	}
	fv.Blocks = blocks

	// Parse the extended header and figure out the start of data
	fv.DataOffset = uint64(fv.HeaderLen)
	if fv.ExtHeaderOffset != 0 && uint64(fv.ExtHeaderOffset) < fv.Length-FirmwareVolumeExtHeaderMinSize {
		// jump to ext header offset.
		r := bytes.NewReader(data[fv.ExtHeaderOffset:])
		if err := binary.Read(r, binary.LittleEndian, &fv.FirmwareVolumeExtHeader); err != nil {
			return nil, fmt.Errorf("unable to parse FV extended header, got: %v", err)
		}
		// TODO: will the ext header ever end before the regular header? I don't believe so. Add a check?
		fv.DataOffset = uint64(fv.ExtHeaderOffset) + uint64(fv.ExtHeaderSize)
	}
	// Make sure DataOffset is 8 byte aligned at least.
	// TODO: handle alignment field in header.
	fv.DataOffset = align8(fv.DataOffset)

	fv.fvType = FVGUIDs[fv.FileSystemGUID]

	// Parse the files.
	// TODO: handle fv data alignment.
	// Start from the end of the fv header.
	lh := fv.Length - FileHeaderMinLength
	for offset, prevLen := fv.DataOffset, uint64(0); offset < lh; offset += prevLen {
		offset = align8(offset)
		file, err := NewFirmwareFile(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("unable to construct firmware file at offset %#x into FV: %v", offset, err)
		}
		if file == nil {
			// We've reached free space. Terminate
			break
		}
		fv.Files = append(fv.Files, *file)
		prevLen = file.Header.ExtendedSize
	}

	// slice the buffer
	fv.buf = data[:fv.Length]
	return &fv, nil
}
