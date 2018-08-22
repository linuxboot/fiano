package uefi

import (
	"testing"
)

var (
	// File headers
	// Hardcoded checksums for testing :(
	// I don't know how to do it better without rewriting or calling code under test.
	emptyPadHeader = append(FFGUID[:],
		[]byte{8, EmptyBodyChecksum, byte(FVFileTypePad), 0, FileHeaderMinLength, 0x00, 0x00, 0xF8}...) // Empty pad file header with no data
	goodFreeFormHeader = append(FFGUID[:],
		[]byte{202, EmptyBodyChecksum, byte(FVFileTypeFreeForm), 0, FileHeaderMinLength, 0x00, 0x00, 0xF8}...) // Empty freeform file header with no data
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
	goodFreeFormFile[20] = byte(FileHeaderMinLength + len(tinySec) + 2 + len(linuxSec) + len(smallSec))

	badFreeFormFile = make([]byte, len(goodFreeFormFile))
	copy(badFreeFormFile, goodFreeFormFile)
	badFreeFormFile[16] = 0 // Zero out checksum
}

func TestValidateFile(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msgs []string
	}{
		{"emptyPadFile", emptyPadFile, nil},
		{"badFreeFormFile", badFreeFormFile, []string{"file FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF header checksum failure! sum was 54"}},
		{"goodFreeFormFile", goodFreeFormFile, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := NewFile(test.buf)
			if err != nil {
				t.Fatalf("Error was not expected, got %v", err.Error())
			}
			errs := f.Validate()
			if len(errs) != len(test.msgs) {
				t.Errorf("Errors mismatched, wanted \n%v\n, got \n%v\n", test.msgs, errs)
			} else {
				for i := range errs {
					if errs[i].Error() != test.msgs[i] {
						t.Errorf("Error mismatched, wanted \n%v\n, got \n%v\n", test.msgs[i], errs[i].Error())
					}
				}
			}
		})
	}
}

func TestNewFile(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msg  string
	}{
		{"emptyFile", emptyFile, "EOF"},
		{"emptyPadFile", emptyPadFile, ""},
		{"badFreeFormFile", badFreeFormFile, ""},
		{"goodFreeFormFile", goodFreeFormFile, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewFile(test.buf)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
		})
	}
}
