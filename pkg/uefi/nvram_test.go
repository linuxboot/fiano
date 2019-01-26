// Copyright 2019 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uefi

import (
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
)

func TestNVarAttribute_IsValid(t *testing.T) {
	var tests = []struct {
		name string
		attr NVarAttribute
		res  bool
	}{
		{"zero", NVarAttribute(0), false},
		{"validOnly", NVarEntryValid, true},
		{"NotValid", NVarEntryValid ^ 0xff, false},
		{"ff", NVarAttribute(0xff), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if res := test.attr.IsValid(); res != test.res {
				t.Errorf("IsValid wrong result!, input was %#x, wanted %v, got %v", test.attr, test.res, res)
			}
		})
	}
}

var (
	// Small buffs to reuse
	emptyNVarBuf       = []byte{}
	erasedSmallNVarBuf = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	erased16NVarBuf    = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	signatureNVarBuf   = []byte{0x4E, 0x56, 0x41, 0x52}
	noNextNVarBuf      = []byte{0xFF, 0xFF, 0xFF}
)
var (
	// Header & NVar Tests
	headerOnlyEmptyNVar      = append(append(append(signatureNVarBuf[:], []byte{10, 0}...), noNextNVarBuf...), byte(NVarEntryValid|NVarEntryDataOnly))
	badIncompleteNVar        = append(append(append(signatureNVarBuf[:], []byte{11, 0}...), noNextNVarBuf...), byte(NVarEntryValid|NVarEntryDataOnly))
	invalidNVar              = append(append(append(signatureNVarBuf[:], []byte{10, 0}...), noNextNVarBuf...), byte(0))
	badMissingGUIDNVar       = append(append(append(signatureNVarBuf[:], []byte{10, 0}...), noNextNVarBuf...), byte(NVarEntryValid|NVarEntryASCIIName))
	badMissingNameEndNVAR    = append(append(append(signatureNVarBuf[:], []byte{15, 0}...), noNextNVarBuf...), []byte{byte(NVarEntryValid | NVarEntryASCIIName), 0, byte('T'), byte('e'), byte('s'), byte('t')}...)
	stored0GUIDASCIINameNVar = append(append(append(signatureNVarBuf[:], []byte{16, 0}...), noNextNVarBuf...), []byte{byte(NVarEntryValid | NVarEntryASCIIName), 0, byte('T'), byte('e'), byte('s'), byte('t'), 0}...)
	stored1GUIDASCIINameNVar = append(append(append(signatureNVarBuf[:], []byte{16, 0}...), noNextNVarBuf...), []byte{byte(NVarEntryValid | NVarEntryASCIIName), 1, byte('T'), byte('e'), byte('s'), byte('t'), 0}...)
)
var (
	testNVarStore = append(append(headerOnlyEmptyNVar, stored0GUIDASCIINameNVar...), erased16NVarBuf...)
)

func TestNVar_parseHeader(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msg  string
	}{
		{"emptyNVarBuf", emptyNVarBuf, "EOF"},
		{"erasedSmallNVarBuf", erasedSmallNVarBuf, "unexpected EOF"},
		{"erased16NVarBuf", erased16NVarBuf, "NVAR Signature not found"},
		{"badIncompleteNVar", badIncompleteNVar, "NVAR Size bigger than remaining size"},
		{"goodEmptyNVar", headerOnlyEmptyNVar, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var v NVar
			err := v.parseHeader(test.buf)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if err == nil && v.DataOffset != 10 {
				t.Errorf("Invalid DataOffset, expected 10 got %v", v.DataOffset)
			}
		})
	}
}

const NoNVarEntry NVarEntryType = 0xFF

func TestNewNVar_noStore(t *testing.T) {
	var tests = []struct {
		name       string
		buf        []byte
		msg        string
		t          NVarEntryType
		DataOffset int64
	}{
		{"emptyNVarBuf", emptyNVarBuf, "", NoNVarEntry, 0},
		{"erasedSmallNVarBuf", erasedSmallNVarBuf, "", NoNVarEntry, 0},
		{"erased16NVarBuf", erased16NVarBuf, "", NoNVarEntry, 0},
		{"badIncompleteNVar", badIncompleteNVar, "NVAR Size bigger than remaining size", InvalidNVarEntry, 10},
		{"goodEmptyNVar", headerOnlyEmptyNVar, "", InvalidLinkNVarEntry, 10},
		{"invalidNVar", invalidNVar, "", InvalidNVarEntry, 10},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var s NVarStore
			Attributes.ErasePolarity = 0xFF
			v, err := newNVar(test.buf, 0, &s)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if err != nil {
				// expected error
				return
			}
			if test.t == NoNVarEntry {
				if v != nil {
					t.Errorf("No NVar expected got \n%v\n", v)

				}
				return
			} else if v == nil {
				t.Error("No NVar returned")
				return

			}

			if v.Type != test.t {
				t.Errorf("Invalid Type, expected %v got %v", test.t, v.Type)
			}
			if v.DataOffset != test.DataOffset {
				t.Errorf("Invalid DataOffset, expected %v got %v", test.DataOffset, v.DataOffset)
			}
		})
	}
}

func TestNewNVar_ErasePolarity(t *testing.T) {
	var tests = []struct {
		name string
		ep   byte
		msg  string
	}{
		{"ErasePolarity", 0xF0, "erase polarity not 0x00 or 0xFF, got 0xf0"},
		{"ErasePolarity", 0x00, ""},
		{"ErasePolarity", 0xFF, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var s NVarStore
			Attributes.ErasePolarity = test.ep
			v, err := newNVar(headerOnlyEmptyNVar, 0, &s)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if err == nil && v == nil {
				t.Error("No NVar returned")
			}
		})
	}
}

func TestNewNVar_Store(t *testing.T) {
	var tests = []struct {
		name       string
		offset     uint64
		buf        []byte
		msg        string
		t          NVarEntryType
		DataOffset int64
		GUID       *guid.GUID
		Name       string
	}{
		{"goodEmptyNVar", 123, headerOnlyEmptyNVar, "", DataNVarEntry, 10, guid.MustParse("2df19db9-a1b4-4b02-b4bb-5ddb4866e13f"), "Stored"},
		{"badMissingGUIDNVar", 0, badMissingGUIDNVar, "EOF", FullNVarEntry, 16, nil, ""},
		{"badMissingNameEndNVAR", 0, badMissingNameEndNVAR, "EOF", FullNVarEntry, 15, nil, ""},
		{"stored0GUIDASCIINameNVar", 0, stored0GUIDASCIINameNVar, "", FullNVarEntry, 16, FFGUID, "Test"},
		{"stored1GUIDASCIINameNVar", 0, stored1GUIDASCIINameNVar, "", FullNVarEntry, 16, ZeroGUID, "Test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storedVar := NVar{GUID: *guid.MustParse("2df19db9-a1b4-4b02-b4bb-5ddb4866e13f"), Name: "Stored", Type: LinkNVarEntry, NextOffset: 123}
			invalidVar := NVar{Type: InvalidNVarEntry}
			s := NVarStore{buf: erased16NVarBuf}
			s.Entries = append(s.Entries, &invalidVar, &storedVar)
			Attributes.ErasePolarity = 0xFF
			v, err := newNVar(test.buf, test.offset, &s)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if err != nil {
				// expected error
				return
			}
			if test.t == NoNVarEntry {
				if v != nil {
					t.Errorf("No NVar expected got \n%v\n", v)

				}
				return
			} else if v == nil {
				t.Error("No NVar returned")
				return

			}

			if v.Type != test.t {
				t.Errorf("Invalid Type, expected %v got %v", test.t, v.Type)
			}
			if v.DataOffset != test.DataOffset {
				t.Errorf("Invalid DataOffset, expected %v got %v", test.DataOffset, v.DataOffset)
			}
			if test.GUID != nil && v.GUID != *test.GUID {
				t.Errorf("Invalid GUID, expected %v got %v", *test.GUID, v.GUID)
			}
			if v.Name != test.Name {
				t.Errorf("Invalid Name, expected %v got %v", test.Name, v.Name)
			}
		})
	}
}

func TestNVar_parseContent(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msg  string
	}{
		{"emptyNVarBuf", emptyNVarBuf, "EOF"},
		{"tooSmallNVarBuf", noNextNVarBuf, "unexpected EOF"},
		{"erasedSmallNVarBuf", erasedSmallNVarBuf, "NVAR Signature not found"},
		{"badIncompleteNVar", badIncompleteNVar, "error parsing NVAR store in var StoreInVar: error parsing NVAR entry at offset 0x0: NVAR Size bigger than remaining size"},
		{"goodEmptyNVar", headerOnlyEmptyNVar, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := NVar{Name: "StoreInVar"}
			Attributes.ErasePolarity = 0xFF
			err := v.parseContent(test.buf)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if err == nil && v.NVarStore == nil {
				t.Errorf("No NVarStore parsed, got nil")
			}
		})
	}
}

func TestNVar_NewNVarStore(t *testing.T) {
	var tests = []struct {
		name  string
		buf   []byte
		msg   string
		count int
	}{
		{"emptyNVarBuf", emptyNVarBuf, "", 0},
		{"tooSmallNVarBuf", noNextNVarBuf, "", 0},
		{"erasedSmallNVarBuf", erasedSmallNVarBuf, "", 0},
		{"erased16NVarBuf", erased16NVarBuf, "", 0},
		{"badIncompleteNVar", badIncompleteNVar, "error parsing NVAR entry at offset 0x0: NVAR Size bigger than remaining size", 0},
		{"goodEmptyNVar", headerOnlyEmptyNVar, "", 1},
		{"testNVarStore", testNVarStore, "", 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			Attributes.ErasePolarity = 0xFF
			s, err := NewNVarStore(test.buf)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			} else if err == nil && len(s.Entries) != test.count {
				t.Errorf("Wrong number of NVar found, expected %v got %v", test.count, len(s.Entries))
			}
		})
	}
}
