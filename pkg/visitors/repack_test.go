// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"encoding/binary"
	"log"
	"testing"

	"github.com/linuxboot/fiano/pkg/compression"
	"github.com/linuxboot/fiano/pkg/guid"
	"github.com/linuxboot/fiano/pkg/uefi"
)

var (
	file1GUID = guid.MustParse("01234567-89AB-CDEF-0123-456789ABCDEF")
	file2GUID = guid.MustParse("DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF")

	ss1 *uefi.Section
	ss2 *uefi.Section
	rs1 *uefi.Section
	cs1 *uefi.Section
	cs2 *uefi.Section

	f1  *uefi.File
	f2  *uefi.File
	pfv *uefi.FirmwareVolume

	err error
)

func init() {
	// Level 2 sections: sections that are inside compressed sections.
	ss1, err = uefi.CreateSection(uefi.SectionTypeRaw, []byte("Subsection 1 data"), nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	ss2, err = uefi.CreateSection(uefi.SectionTypeRaw, []byte("Subsection 2 data"), nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Level 1 sections: includes guid defined compression sections.
	cs1, err = uefi.CreateSection(uefi.SectionTypeGUIDDefined, nil, []uefi.Firmware{ss1}, &compression.LZMAGUID)
	if err != nil {
		log.Fatal(err)
	}
	rs1, err = uefi.CreateSection(uefi.SectionTypeRaw, []byte("Raw section data"), nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	cs2, err = uefi.CreateSection(uefi.SectionTypeGUIDDefined, nil, []uefi.Firmware{ss2}, &compression.LZMAGUID)
	if err != nil {
		log.Fatal(err)
	}

	// Sample Files
	f1 = &uefi.File{}
	f1.Header.GUID = *file1GUID
	f1.Header.Type = uefi.FVFileTypeDriver
	f1.Sections = []*uefi.Section{rs1, cs1}

	f2 = &uefi.File{}
	f2.Header.GUID = *file2GUID
	f2.Header.Type = uefi.FVFileTypeDriver
	f2.Sections = []*uefi.Section{cs2}

	// Sample original firmware volume
	pfv = &uefi.FirmwareVolume{}
	pfv.FileSystemGUID = *uefi.FFS2
	pfv.Signature = binary.LittleEndian.Uint32([]byte("_FVH"))
	pfv.Attributes = 0x89ABCDEF
	pfv.Revision = 0xFF
	pfv.Blocks = []uefi.Block{{Count: 1024, Size: 4096}}
	pfv.HeaderLen = 56
	pfv.Files = []*uefi.File{f1, f2}
}

func TestRepack(t *testing.T) {
	if err := repackFV(pfv); err != nil {
		t.Fatalf("Failed to repack firmware volume, got %v", err)
	}

	// pfv should have repacked firmware volume
	if fvlen := len(pfv.Files); fvlen != 1 {
		t.Fatalf("There should be exactly one file in repacked FV! got %v files", fvlen)
	}

	f := pfv.Files[0]
	if f.Header.Type != uefi.FVFileTypeVolumeImage {
		t.Fatalf("File should be of type EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE, got %s", f.Header.Type)
	}
	if flen := len(f.Sections); flen != 1 {
		t.Fatalf("Wrong number of sections in file, got %v", flen)
	}

	cs := f.Sections[0]
	if cs.Header.Type != uefi.SectionTypeGUIDDefined {
		t.Fatalf("Section should be of type EFI_SECTION_GUID_DEFINED, got %s", cs.Header.Type)
	}
	if elen := len(cs.Encapsulated); elen != 1 {
		t.Fatalf("Wrong number of encapsulated section in compressed section, got %v", elen)
	}

	vs, ok := cs.Encapsulated[0].Value.(*uefi.Section)
	if !ok {
		t.Fatal("Encapsulated section was not of type uefi.Section")
	}
	if vs.Header.Type != uefi.SectionTypeFirmwareVolumeImage {
		t.Fatalf("Section should be of type EFI_SECTION_VOLUME_IMAGE, got %s", vs.Header.Type)
	}
	if elen := len(vs.Encapsulated); elen != 1 {
		t.Fatalf("Wrong number of encapsulated section in volume image section, got %v", elen)
	}

	nfv, ok := vs.Encapsulated[0].Value.(*uefi.FirmwareVolume)
	if !ok {
		t.Fatal("Volume Image Section did not contain firmware volume!")
	}
	if fvlen := len(nfv.Files); fvlen != 2 {
		t.Fatalf("There should be 2 files in repacked FV! got %v files", fvlen)
	}
	// Check file pointers.
	if nfv.Files[0] != f1 {
		t.Fatalf("file 1 mismatch: expected %v, got %v", f1, nfv.Files[0])
	}
	if nfv.Files[1] != f2 {
		t.Fatalf("file 2 mismatch: expected %v, got %v", f2, nfv.Files[1])
	}

	if slen := len(f1.Sections); slen != 2 {
		t.Fatalf("There should be 2 sections in file 1! got %v sections", slen)
	}
	if f1.Sections[0] != rs1 {
		t.Fatalf("file 1 section 1 mismatch: expected %v, got %v", rs1, f1.Sections[0])
	}
	if f1.Sections[1] != ss1 {
		t.Fatalf("file 1 section 1 mismatch: expected %v, got %v", ss1, f1.Sections[1])
	}

	if slen := len(f2.Sections); slen != 1 {
		t.Fatalf("There should be 1 sections in file 2! got %v sections", slen)
	}
	if f2.Sections[0] != ss2 {
		t.Fatalf("file 2 mismatch: expected %v, got %v", ss2, f2.Sections[0])
	}
}
