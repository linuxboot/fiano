package uefi

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var (
	// Section examples
	emptySec     = make([]byte, 0)                                                     // Empty section
	tinySec      = []byte{4, 0, 0, byte(SectionTypeRaw)}                               // Section header with no data
	wrongSizeSec = append([]byte{40, 0, 0, byte(SectionTypeRaw)}, make([]byte, 20)...) // Section with a size mismatch
	smallSec     = append([]byte{24, 0, 0, byte(SectionTypeRaw)}, make([]byte, 20)...) // 24 byte Section
	linuxSec     = []byte{0x10, 0x00, 0x00, 0x15, 0x4c, 0x00, 0x69, 0x00,
		0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x00, 0x00} // Linux UI section
)

func TestUISection(t *testing.T) {
	var tests = []struct {
		buf       []byte
		fileOrder int
		val       string
	}{
		{linuxSec, 1, "Linux"},
		{smallSec, 1, ""},
	}
	for _, test := range tests {
		s, err := NewSection(test.buf, test.fileOrder)
		if err != nil {
			t.Fatalf("Unable to parse section object %v, got %v", test.buf, err.Error())
		}
		if s.Name != test.val {
			t.Errorf("Section Name field mismatch, expected \"%v\", got \"%v\"", test.val, s.Name)
		}
	}
}

func TestExtractAssemble(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "section-test")
	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}

	defer os.RemoveAll(tmpDir)

	var tests = []struct {
		buf       []byte
		fileOrder int
	}{
		{tinySec, 0},
		{tinySec, 1},
		{smallSec, 0},
		{smallSec, 1},
		{linuxSec, 0},
		{linuxSec, 1},
	}
	for _, test := range tests {
		s, err := NewSection(test.buf, test.fileOrder)
		if err != nil {
			t.Fatalf("Unable to parse section object %v, got %v", test.buf, err.Error())
		}
		if err = s.Extract(tmpDir); err != nil {
			t.Fatalf("Unable to extract section %v, got %v", test.buf, err.Error())
		}
		nb, err := s.Assemble()
		if len(test.buf) != len(nb) {
			t.Fatalf("Binaries differ! original \n%v\n assembled \n%v\n", test.buf, nb)
		}
		for i := range test.buf {
			if test.buf[i] != nb[i] {
				t.Fatalf("Binaries differ! original \n%v\n assembled \n%v\n", test.buf, nb)
			}
		}
	}
}

func TestNewSection(t *testing.T) {
	var tests = []struct {
		buf       []byte
		fileOrder int
		msg       string
	}{
		{emptySec, 0, "EOF"},
		{wrongSizeSec, 0,
			fmt.Sprintf("section size mismatch! Section has size %v, but buffer is %v bytes big",
				40, len(wrongSizeSec))},
		{tinySec, 0, ""},
		{smallSec, 0, ""},
		{linuxSec, 0, ""},
	}
	for _, test := range tests {
		_, err := NewSection(test.buf, test.fileOrder)
		if err == nil && test.msg != "" {
			t.Errorf("Error was not returned, expected %v", test.msg)
		} else if err != nil && err.Error() != test.msg {
			t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
		}
	}
}
