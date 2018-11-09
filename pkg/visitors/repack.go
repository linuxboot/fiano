// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/linuxboot/fiano/pkg/compression"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// Repack repacks a per file compressed FV into a singularly compressed nested FV
type Repack struct {
	// Input
	Predicate func(f uefi.Firmware) bool

	// Matched File
	FileMatch *uefi.File
}

// removeFileCompression goes through a newly created, nested firmware volume
// and removes the first level compressed section.
func removeFileCompression(nfv *uefi.FirmwareVolume) error {
	for _, f := range nfv.Files {
		newSectionList := []*uefi.Section{}
		for _, s := range f.Sections {
			if s.Header.Type != uefi.SectionTypeGUIDDefined {
				// This doesn't have a compressed section
				newSectionList = append(newSectionList, s)
				continue
			}
			gdh := s.TypeSpecific.Header.(*uefi.SectionGUIDDefined)
			if guid := gdh.GUID; guid != compression.LZMAGUID && guid != compression.LZMAX86GUID {
				// This doesn't have a compressed section
				newSectionList = append(newSectionList, s)
				continue
			}
			// This is a compressed section we understand, remove it and add children directly to file.
			for _, es := range s.Encapsulated {
				child, ok := es.Value.(*uefi.Section)
				if !ok {
					// This should never happen, die
					return fmt.Errorf("file %v has non sections inside a compressed section, discarding", f.Header.GUID)
				}
				newSectionList = append(newSectionList, child)
			}
		}
		f.Sections = newSectionList
	}
	return nil
}

func createFirmwareVolume(pfv *uefi.FirmwareVolume) (*uefi.FirmwareVolume, error) {
	nfv := &uefi.FirmwareVolume{} // new Firmware Volume

	// Create new firmware volume that encloses all the old files.
	// Set up volume header first.
	nfv.FileSystemGUID = *uefi.FFS2
	nfv.Signature = binary.LittleEndian.Uint32([]byte("_FVH"))
	// Copy over attributes from parent. We may want to change this in the future.
	// We don't need the alignment fields since we're nested,
	// so we really only need the lower 16 bits.
	nfv.Attributes = pfv.Attributes & 0x0000FFFF
	nfv.Revision = pfv.Revision
	// Copy and use parent's block size. We assume there's only one nonzero block entry
	nfv.Blocks = make([]uefi.Block, 2)
	if bLen := len(pfv.Blocks); bLen < 1 {
		// According to the spec, should always be two blocks, one null to terminate the block list, but
		// some bioses are not compliant.
		return nil, fmt.Errorf("parent firmware volume block list is too short: need at least 1, got %v",
			bLen)
	}
	if pfv.Blocks[0].Size == 0 {
		return nil, errors.New("first parent firmware volume block has 0 block size, malformed parent block")
	}
	// We use the parent's block size
	nfv.Blocks[0] = uefi.Block{Size: pfv.Blocks[0].Size}
	nfv.Blocks[1] = uefi.Block{}

	// Calculate the HeaderLen field
	nfv.HeaderLen = uint16(uefi.FirmwareVolumeFixedHeaderSize + int(unsafe.Sizeof(uefi.Block{}))*len(nfv.Blocks))

	// Create firmware volume metadata
	nfv.DataOffset = uint64(nfv.HeaderLen) // Since we don't have the extended header, HeaderLen is DataOffset.
	nfv.Length = nfv.DataOffset
	nfv.Resizable = true // This is a nested firmware volume, so we can resize it as needed.

	// Generate binary header.
	header := new(bytes.Buffer)
	err := binary.Write(header, binary.LittleEndian, nfv.FirmwareVolumeFixedHeader)
	if err != nil {
		return nil, fmt.Errorf("unable to construct binary header of nested firmware volume: got %v", err)
	}
	for _, b := range nfv.Blocks {
		err = binary.Write(header, binary.LittleEndian, b)
		if err != nil {
			return nil, fmt.Errorf("unable to construct binary header of nested firmware volume: got %v", err)
		}

	}
	nfv.SetBuf(header.Bytes())
	// Copy out parent's files
	nfv.Files = append([]*uefi.File{}, pfv.Files...)

	return nfv, nil
}

func createVolumeImageFile(cs *uefi.Section) (*uefi.File, error) {
	f := &uefi.File{}

	f.Header.Type = uefi.FVFileTypeVolumeImage
	f.Sections = []*uefi.Section{cs}

	// Call assemble to populate cs's buffer. then sha1 it for the guid.
	a := &Assemble{}
	if err := a.Run(cs); err != nil {
		return nil, err
	}
	sum := sha1.Sum(cs.Buf())
	copy(f.Header.GUID[:], sum[:]) // GUIDs are smaller, so only 16 bytes are copied

	return f, nil
}

func repackFV(fv *uefi.FirmwareVolume) error {
	// fv should be the pointer to the enclosing firmware volume that needs to be repacked.

	// Create new Firmware Volume.
	// This copies out the parent list of files and assigns it to the new fv
	nfv, err := createFirmwareVolume(fv)
	if err != nil {
		return err
	}

	// Remove per file compression
	if err = removeFileCompression(nfv); err != nil {
		return err
	}

	// Create new Volume Image section
	vs, err := uefi.CreateSection(uefi.SectionTypeFirmwareVolumeImage, []byte{}, []uefi.Firmware{nfv}, nil)
	if err != nil {
		return err
	}

	// Create new compressed section
	cs, err := uefi.CreateSection(uefi.SectionTypeGUIDDefined, []byte{}, []uefi.Firmware{vs}, &compression.LZMAGUID)
	if err != nil {
		return err
	}

	// Create new FV image file
	file, err := createVolumeImageFile(cs)
	if err != nil {
		return err
	}

	// Set new file as the only firmware file in the original fv.
	fv.Files = append([]*uefi.File{}, file)
	return nil
}

// Run wraps Visit and performs some setup and teardown tasks.
func (v *Repack) Run(f uefi.Firmware) error {
	// Check that fv being repacked isn't already nested.
	// First run "find" to generate a position to insert into.
	find := Find{
		Predicate: v.Predicate,
	}
	if err := find.Run(f); err != nil {
		return err
	}

	if numMatch := len(find.Matches); numMatch > 1 {
		return fmt.Errorf("more than one match, only one match allowed! got %v", find.Matches)
	} else if numMatch == 0 {
		return errors.New("no matches found")
	}

	// Find should only match a file or a firmware volume. If it's an FV, we can
	// edit the FV directly.
	if fvMatch, ok := find.Matches[0].(*uefi.FirmwareVolume); ok {
		// Call repack function.
		return repackFV(fvMatch)
	}
	var ok bool
	if v.FileMatch, ok = find.Matches[0].(*uefi.File); !ok {
		return fmt.Errorf("match was not a file or a firmware volume: got %T, unable to insert", find.Matches[0])
	}
	// Match is a file, apply visitor.
	if err := f.Apply(v); err != nil {
		return err
	}

	// Assemble the tree just to make sure things are right.
	a := &Assemble{}
	return a.Run(f)
}

// Visit applies the Repack visitor to any Firmware type.
func (v *Repack) Visit(f uefi.Firmware) error {
	switch f := f.(type) {
	case *uefi.FirmwareVolume:
		for i := 0; i < len(f.Files); i++ {
			if f.Files[i] == v.FileMatch {
				// call repack function.
				return repackFV(f)
			}
		}
	}

	return f.ApplyChildren(v)
}

func init() {
	RegisterCLI("repack",
		"repack a per file compressed fv to a nested compressed fv", 1,
		func(args []string) (uefi.Visitor, error) {
			pred, err := FindFileFVPredicate(args[0])
			if err != nil {
				return nil, err
			}

			// Repack File.
			return &Repack{
				Predicate: pred,
			}, nil
		})
}
