// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/linuxboot/fiano/pkg/log"
	"github.com/linuxboot/fiano/pkg/uefi"
)

var (
	// FV examples
	sampleFV []byte // Sample FV from OVMF
)

func init() {
	var err error
	sampleFV, err = ioutil.ReadFile("../../integration/roms/ovmfSECFV.fv")
	if err != nil {
		log.Fatalf("%v", err)
	}
}

var (
	// File headers
	// Hardcoded checksums for testing :(
	// I don't know how to do it better without rewriting or calling code under test.
	emptyPadHeader = append(uefi.FFGUID[:],
		[]byte{8, uefi.EmptyBodyChecksum, byte(uefi.FVFileTypePad), 0, uefi.FileHeaderMinLength, 0x00, 0x00, 0xF8}...) // Empty pad file header with no data
	goodFreeFormHeader = append(uefi.FFGUID[:],
		[]byte{202, uefi.EmptyBodyChecksum, byte(uefi.FVFileTypeFreeForm), 0, uefi.FileHeaderMinLength, 0x00, 0x00, 0xF8}...) // Empty freeform file header with no data
	nvarStoreHeader = append(uefi.NVAR[:],
		[]byte{182, uefi.EmptyBodyChecksum, byte(uefi.FVFileTypeRaw), 0, uefi.FileHeaderMinLength, 0x00, 0x00, 0xF8}...) // Empty NVAR file header with no data
)

var (
	// File examples
	emptyPadFile     = emptyPadHeader // Empty pad file with no data
	badFreeFormFile  []byte           // File with bad checksum. Should construct fine, but not validate
	goodFreeFormFile []byte           // Good file
	nvarStoreFile    []byte           // File containing an NVarStore
)

func init() {
	goodFreeFormFile = append(goodFreeFormHeader, linuxSec...)
	goodFreeFormFile = append(goodFreeFormFile, smallSec...)
	goodFreeFormFile = append(goodFreeFormFile, []byte{0, 0}...) // Alignment
	goodFreeFormFile = append(goodFreeFormFile, tinySec...)
	goodFreeFormFile[20] = byte(uefi.FileHeaderMinLength + len(tinySec) + 2 + len(linuxSec) + len(smallSec))

	badFreeFormFile = make([]byte, len(goodFreeFormFile))
	copy(badFreeFormFile, goodFreeFormFile)
	badFreeFormFile[16] = 0 // Zero out checksum

	nvarStoreFile = append(nvarStoreHeader, nvarEntryHeader...)
	nvarStoreFile = append(nvarStoreFile, byte(0))
	nvarStoreFile = append(nvarStoreFile, []byte("Test")...)
	nvarStoreFile = append(nvarStoreFile, byte(0))
	nvarStoreFile = append(nvarStoreFile, uefi.FFGUID[:]...)
	nvarStoreFile[20] = byte(uefi.FileHeaderMinLength + len(nvarEntryHeader) + 6 + len(uefi.FFGUID))

}

var (
	// NVAR examples
	nvarEntryHeader = []byte{0x4E, 0x56, 0x41, 0x52, 16, 0, 0xFF, 0xFF, 0xFF, byte(uefi.NVarEntryValid | uefi.NVarEntryASCIIName)}
)

var (
	// Section examples
	tinySec  = []byte{4, 0, 0, byte(uefi.SectionTypeRaw)}                               // Section header with no data
	smallSec = append([]byte{22, 0, 0, byte(uefi.SectionTypeRaw)}, make([]byte, 18)...) // 20 byte Section
	linuxSec = []byte{0x10, 0x00, 0x00, 0x15, 0x4c, 0x00, 0x69, 0x00,
		0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x00, 0x00} // Linux UI section
)

func TestExtractAssembleFile(t *testing.T) {
	var tests = []struct {
		name    string
		origBuf []byte
		newBuf  []byte
	}{
		{"emptyPadFile", emptyPadFile, emptyPadFile},
		{"badFreeFormFile", badFreeFormFile, goodFreeFormFile},
		{"goodFreeFormFile", goodFreeFormFile, goodFreeFormFile},
		{"nvarStoreFile", nvarStoreFile, nvarStoreFile},
	}
	// Set erasepolarity to FF
	uefi.Attributes.ErasePolarity = 0xFF
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "section-test")

			if err != nil {
				t.Fatalf("could not create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			f, err := uefi.NewFile(test.origBuf)
			if err != nil {
				t.Fatalf("Unable to parse file object %v, got %v", test.origBuf, err.Error())
			}
			var fIndex uint64
			if err = f.Apply(&Extract{BasePath: tmpDir, DirPath: ".", Index: &fIndex}); err != nil {
				t.Fatalf("Unable to extract file %v, got %v", test.origBuf, err.Error())
			}
			if err = f.Apply(&ParseDir{BasePath: tmpDir}); err != nil {
				t.Fatalf("Unable to parse files %v, got %v", test.origBuf, err.Error())
			}
			if err = f.Apply(&Assemble{}); err != nil {
				t.Fatalf("Unable to reassemble file %v, got %v", test.origBuf, err.Error())
			}
			nb := f.Buf()
			if len(test.newBuf) != len(nb) {
				t.Fatalf("Binary sizes differ!\n Expected: %v\n Assembled: %v\n", len(test.newBuf), len(nb))
			}
			for i := range test.newBuf {
				if test.newBuf[i] != nb[i] {
					t.Fatalf("Binaries differ at %v!\n Expected: %v\n Assembled: %v\n", i, test.newBuf[i], nb[i])
				}
			}
		})
	}
}

func TestExtractAssembleFV(t *testing.T) {
	var tests = []struct {
		name    string
		origBuf []byte
		newBuf  []byte
	}{
		{"sampleFV", sampleFV, sampleFV},
	}
	// Set erasepolarity to FF
	uefi.Attributes.ErasePolarity = 0xFF
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "section-test")

			if err != nil {
				t.Fatalf("could not create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			fv, err := uefi.NewFirmwareVolume(test.origBuf, 0, false)
			if err != nil {
				t.Fatalf("Unable to parse file object %v, got %v", test.origBuf, err.Error())
			}
			var fIndex uint64
			if err = fv.Apply(&Extract{BasePath: tmpDir, DirPath: ".", Index: &fIndex}); err != nil {
				t.Fatalf("Unable to extract file %v, got %v", test.origBuf, err.Error())
			}
			if err = fv.Apply(&ParseDir{BasePath: tmpDir}); err != nil {
				t.Fatalf("Unable to parse files %v, got %v", test.origBuf, err.Error())
			}
			if err = fv.Apply(&Assemble{}); err != nil {
				t.Fatalf("Unable to reassemble file %v, got %v", test.origBuf, err.Error())
			}
			nb := fv.Buf()
			if len(test.newBuf) != len(nb) {
				t.Fatalf("Binary sizes differ!\n Expected: %v\n Assembled: %v\n", len(test.newBuf), len(nb))
			}
			for i := range test.newBuf {
				if test.newBuf[i] != nb[i] {
					t.Fatalf("Binaries differ at %v!\n Expected: %v\n Assembled: %v\n", i, test.newBuf[i], nb[i])
				}
			}
		})
	}
}

func TestExtractAssembleSection(t *testing.T) {
	var tests = []struct {
		name      string
		buf       []byte
		fileOrder int
	}{
		{"tinySec", tinySec, 0},
		{"tinySec", tinySec, 1},
		{"smallSec", smallSec, 0},
		{"smallSec", smallSec, 1},
		{"linuxSec", linuxSec, 0},
		{"linuxSec", linuxSec, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpDir, err := ioutil.TempDir("", "section-test")

			if err != nil {
				t.Fatalf("could not create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			s, err := uefi.NewSection(test.buf, test.fileOrder)
			if err != nil {
				t.Fatalf("Unable to parse section object %v, got %v", test.buf, err.Error())
			}
			var fIndex uint64
			if err = s.Apply(&Extract{BasePath: tmpDir, DirPath: ".", Index: &fIndex}); err != nil {
				t.Fatalf("Unable to extract section %v, got %v", test.buf, err.Error())
			}
			if err = s.Apply(&ParseDir{BasePath: tmpDir}); err != nil {
				t.Fatalf("Unable to parse files %v, got %v", test.buf, err.Error())
			}
			if err = s.Apply(&Assemble{}); err != nil {
				t.Fatalf("Unable to reassemble file %v, got %v", test.buf, err.Error())
			}
			nb := s.Buf()
			if len(test.buf) != len(nb) {
				t.Fatalf("Binary sizes differ!\n Expected: %v\n Assembled: %v\n", len(test.buf), len(nb))
			}
			for i := range test.buf {
				if test.buf[i] != nb[i] {
					t.Fatalf("Binaries differ at %v!\n Expected: %v\n Assembled: %v\n", i, test.buf[i], nb[i])
				}
			}
		})
	}
}
