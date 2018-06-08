package uefi

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	// Signature examples
	emptySig      = make([]byte, 40)                            // Empty flash signature
	ichSig        = append(FlashSignature, make([]byte, 20)...) // Old ICH version
	pchSig        = append(make([]byte, 16), FlashSignature...) // New PCH version
	misalignedSig = append(append(make([]byte, 10), FlashSignature...),
		make([]byte, 20)...) // Misaligned flash signature
)

func TestFindSignature(t *testing.T) {
	var tests = []struct {
		buf    []byte
		offset int
		msg    string
	}{
		{emptySig, -1,
			fmt.Sprintf("Flash signature not found: first 20 bytes are:\n%s", hex.Dump(emptySig[:20]))},
		{ichSig, 4, ""},
		{pchSig, 20, ""},
		{misalignedSig, -1,
			fmt.Sprintf("Flash signature not found: first 20 bytes are:\n%s", hex.Dump(misalignedSig[:20]))},
	}
	for _, test := range tests {
		f := FlashImage{buf: test.buf}
		offset, err := f.FindSignature()
		if offset != test.offset {
			t.Errorf("Offset was not correct, expected %v, got %v", test.offset, offset)
		}
		if err == nil && test.msg != "" {
			t.Errorf("Error was not returned, expected %v", test.msg)
		} else if err != nil && err.Error() != test.msg {
			t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
		}
	}
}

func TestIsPCH(t *testing.T) {
	var tests = []struct {
		buf []byte
		out bool
	}{
		{emptySig, false},
		{ichSig, false},
		{pchSig, true},
		{misalignedSig, false},
	}
	for _, test := range tests {
		f := FlashImage{buf: test.buf}
		out := f.IsPCH()
		if out != test.out {
			t.Errorf("IsPCH was not correct, expected %v, got %v for \n%s", test.out, out, hex.Dump(test.buf))
		}
	}
}
