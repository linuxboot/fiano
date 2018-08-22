package uefi

import (
	"fmt"
	"testing"
)

var (
	// Section examples
	emptySec     = make([]byte, 0)                                                     // Empty section
	tinySec      = []byte{4, 0, 0, byte(SectionTypeRaw)}                               // Section header with no data
	wrongSizeSec = append([]byte{40, 0, 0, byte(SectionTypeRaw)}, make([]byte, 20)...) // Section with a size mismatch
	largeSizeSec = append([]byte{10, 0, 0, byte(SectionTypeRaw)}, make([]byte, 20)...) // Section with a big buffer
	smallSec     = append([]byte{22, 0, 0, byte(SectionTypeRaw)}, make([]byte, 18)...) // 20 byte Section
	linuxSec     = []byte{0x10, 0x00, 0x00, 0x15, 0x4c, 0x00, 0x69, 0x00,
		0x6e, 0x00, 0x75, 0x00, 0x78, 0x00, 0x00, 0x00} // Linux UI section
)

func TestUISection(t *testing.T) {
	var tests = []struct {
		name      string
		buf       []byte
		fileOrder int
		val       string
	}{
		{"UISection", linuxSec, 1, "Linux"},
		{"nonUISection", smallSec, 1, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewSection(test.buf, test.fileOrder)
			if err != nil {
				t.Fatalf("Unable to parse section object %v, got %v", test.buf, err.Error())
			}
			if s.Name != test.val {
				t.Errorf("Section Name field mismatch, expected \"%v\", got \"%v\"", test.val, s.Name)
			}
		})
	}
}

func TestNewSection(t *testing.T) {
	var tests = []struct {
		name      string
		buf       []byte
		fileOrder int
		msg       string
	}{
		{"emptySec", emptySec, 0, "EOF"},
		{"wrongSizeSec", wrongSizeSec, 0,
			fmt.Sprintf("section size mismatch! Section has size %v, but buffer is %v bytes big",
				40, len(wrongSizeSec))},
		{"largeSizeSec", largeSizeSec, 0, ""},
		{"tinySec", tinySec, 0, ""},
		{"smallSec", smallSec, 0, ""},
		{"linuxSec", linuxSec, 0, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSection(test.buf, test.fileOrder)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
		})
	}
}
