// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package visitors

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/linuxboot/fiano/uefi"
)

var (
	// FV examples
	emptyFV  = []byte{} // Empty file
	sampleFV []byte     // Sample FV from OVMF
)

func init() {
	var err error
	sampleFV, err = ioutil.ReadFile("../integration/roms/ovmfSECFV.fv")
	if err != nil {
		log.Fatal(err)
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
)

var (
	// File examples
	emptyFile        = []byte{}       // Empty file
	emptyPadFile     = emptyPadHeader // Empty pad file with no data
	badFreeFormFile  []byte           // File with bad checksum. Should construct fine, but not validate
	goodFreeFormFile []byte           // Good file
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
}

var (
	// Section examples
	emptySec     = make([]byte, 0)                                                          // Empty section
	tinySec      = []byte{4, 0, 0, byte(uefi.SectionTypeRaw)}                               // Section header with no data
	wrongSizeSec = append([]byte{40, 0, 0, byte(uefi.SectionTypeRaw)}, make([]byte, 20)...) // Section with a size mismatch
	largeSizeSec = append([]byte{10, 0, 0, byte(uefi.SectionTypeRaw)}, make([]byte, 20)...) // Section with a big buffer
	smallSec     = append([]byte{22, 0, 0, byte(uefi.SectionTypeRaw)}, make([]byte, 18)...) // 20 byte Section
	linuxSec     = []byte{0x10, 0x00, 0x00, 0x15, 0x4c, 0x00, 0x69, 0x00,
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
			if err = f.Apply(&Extract{DirPath: tmpDir, Index: &fIndex}); err != nil {
				t.Fatalf("Unable to extract file %v, got %v", test.origBuf, err.Error())
			}
			nb, err := f.Assemble()
			if len(test.newBuf) != len(nb) {
				t.Fatalf("Binaries differ! expected \n%v\n assembled \n%v\n", test.newBuf, nb)
			}
			for i := range test.newBuf {
				if test.newBuf[i] != nb[i] {
					t.Fatalf("Binaries differ! expected \n%v\n assembled \n%v\n", test.newBuf, nb)
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

			fv, err := uefi.NewFirmwareVolume(test.origBuf, 0)
			if err != nil {
				t.Fatalf("Unable to parse file object %v, got %v", test.origBuf, err.Error())
			}
			var fIndex uint64
			if err = fv.Apply(&Extract{DirPath: tmpDir, Index: &fIndex}); err != nil {
				t.Fatalf("Unable to extract file %v, got %v", test.origBuf, err.Error())
			}
			nb, err := fv.Assemble()
			if len(test.newBuf) != len(nb) {
				t.Fatalf("Binaries differ! expected \n%v\n assembled \n%v\n", test.newBuf, nb)
			}
			for i := range test.newBuf {
				if test.newBuf[i] != nb[i] {
					t.Fatalf("Binaries differ! expected \n%v\n assembled \n%v\n", test.newBuf, nb)
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
			if err = s.Apply(&Extract{DirPath: tmpDir, Index: &fIndex}); err != nil {
				t.Fatalf("Unable to extract section %v, got %v", test.buf, err.Error())
			}
			nb, err := s.Assemble()
			if err != nil {
				t.Fatal(err)
			}
			if len(test.buf) != len(nb) {
				t.Fatalf("Binaries differ! original \n%v\n assembled \n%v\n", test.buf, nb)
			}
			for i := range test.buf {
				if test.buf[i] != nb[i] {
					t.Fatalf("Binaries differ! original \n%v\n assembled \n%v\n", test.buf, nb)
				}
			}
		})
	}
}
