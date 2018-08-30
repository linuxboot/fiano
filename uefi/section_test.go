// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/linuxboot/fiano/uuid"
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

func TestParseDepEx(t *testing.T) {
	var tests = []struct {
		name string
		in   []byte
		out  []DepExOp
		err  string
	}{
		{
			name: "empty",
			in:   []byte{},
			err:  "invalid DEPEX, no END",
		},
		{
			name: "end",
			in:   []byte{0x08},
			out:  []DepExOp{{OpCode: "END"}},
		},
		{
			name: "no end",
			in:   []byte{0x06},
			err:  "invalid DEPEX, no END",
		},
		{
			name: "simple",
			in:   []byte{0x06, 0x08},
			out:  []DepExOp{{OpCode: "TRUE"}, {OpCode: "END"}},
		},
		{
			name: "spec example",
			// Example from the Platform Initialization Specification, Vol. 2, Chapter 10.
			in: []byte{
				0x02, // PUSH
				0xF6, 0x3F, 0x5E, 0x66, 0xCC, 0x46, 0xD4, 0x11,
				0x9A, 0x38, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
				0x02, // PUSH
				0xB1, 0xCC, 0xBA, 0x26, 0x42, 0x6F, 0xD4, 0x11,
				0xBC, 0xE7, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81,
				0x03, // AND
				0x02, // PUSH
				0xB2, 0xCC, 0xBA, 0x26, 0x42, 0x6F, 0xD4, 0x11,
				0xBC, 0xE7, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81,
				0x02, // PUSH
				0x72, 0x70, 0xA9, 0x1D, 0xDC, 0xBD, 0x30, 0x4B,
				0x99, 0xF1, 0x72, 0xA0, 0xB5, 0x6F, 0xFF, 0x2A,
				0x03, // AND
				0x03, // AND
				0x02, // PUSH
				0x87, 0xAC, 0xCF, 0x27, 0xCC, 0x46, 0xD4, 0x11,
				0x9A, 0x38, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
				0x02, // PUSH
				0x88, 0xAC, 0xCF, 0x27, 0xCC, 0x46, 0xD4, 0x11,
				0x9A, 0x38, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
				0x03, // AND
				0x02, // PUSH
				0x53, 0x82, 0xD0, 0x96, 0x83, 0x84, 0xD4, 0x11,
				0xBC, 0xF1, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81,
				0x02, // PUSH
				0xE3, 0x23, 0x64, 0xA4, 0x17, 0x46, 0xF1, 0x49,
				0xB9, 0xFF, 0xD1, 0xBF, 0xA9, 0x11, 0x58, 0x39,
				0x02, // PUSH
				0xB3, 0xCC, 0xBA, 0x26, 0x42, 0x6F, 0xD4, 0x11,
				0xBC, 0xE7, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81,
				0x03, // AND
				0x02, // PUSH
				0xE2, 0x68, 0x56, 0x1E, 0x81, 0x84, 0xD4, 0x11,
				0xBC, 0xF1, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81,
				0x02, // PUSH
				0x18, 0xF8, 0x41, 0x64, 0x62, 0x63, 0x44, 0x4E,
				0xB5, 0x70, 0x7D, 0xBA, 0x31, 0xDD, 0x24, 0x53,
				0x03, // AND
				0x03, // AND
				0x03, // AND
				0x02, // PUSH
				0xF5, 0x3F, 0x5E, 0x66, 0xCC, 0x46, 0xD4, 0x11,
				0x9A, 0x38, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
				0x03, // AND
				0x08, // END
			},
			out: []DepExOp{
				{OpCode: "PUSH", GUID: uuid.MustParse("665E3FF6-46CC-11D4-9A38-0090273FC14D")},
				{OpCode: "PUSH", GUID: uuid.MustParse("26BACCB1-6F42-11D4-BCE7-0080C73C8881")},
				{OpCode: "AND"},
				{OpCode: "PUSH", GUID: uuid.MustParse("26BACCB2-6F42-11D4-BCE7-0080C73C8881")},
				{OpCode: "PUSH", GUID: uuid.MustParse("1DA97072-BDDC-4B30-99F1-72A0B56FFF2A")},
				{OpCode: "AND"},
				{OpCode: "AND"},
				{OpCode: "PUSH", GUID: uuid.MustParse("27CFAC87-46CC-11D4-9A38-0090273FC14D")},
				{OpCode: "PUSH", GUID: uuid.MustParse("27CFAC88-46CC-11D4-9A38-0090273FC14D")},
				{OpCode: "AND"},
				{OpCode: "PUSH", GUID: uuid.MustParse("96D08253-8483-11D4-BCF1-0080C73C8881")},
				{OpCode: "PUSH", GUID: uuid.MustParse("A46423E3-4617-49F1-B9FF-D1BFA9115839")},
				{OpCode: "PUSH", GUID: uuid.MustParse("26BACCB3-6F42-11D4-BCE7-0080C73C8881")},
				{OpCode: "AND"},
				{OpCode: "PUSH", GUID: uuid.MustParse("1E5668E2-8481-11D4-BCF1-0080C73C8881")},
				{OpCode: "PUSH", GUID: uuid.MustParse("6441F818-6362-4E44-B570-7DBA31DD2453")},
				{OpCode: "AND"},
				{OpCode: "AND"},
				{OpCode: "AND"},
				{OpCode: "PUSH", GUID: uuid.MustParse("665E3FF5-46CC-11D4-9A38-0090273FC14D")},
				{OpCode: "AND"},
				{OpCode: "END"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			depEx, err := parseDepEx(tt.in)
			if tt.err == "" {
				// Expects no error.
				if err != nil {
					t.Fatalf("unexpected error, %v", err)
				}
				if !reflect.DeepEqual(depEx, tt.out) {
					t.Fatalf("expected %s, got %s", tt.out, depEx)
				}
			} else {
				// Expects error.
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.err != err.Error() {
					t.Fatalf("expected error %q, got %q", tt.err, err)
				}
			}
		})
	}
}
