package uefi

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestUnmarshalTypedFirmware(t *testing.T) {
	inFirmware := MakeTyped(&Section{Name: "CHARLIE"})

	j, err := json.Marshal(inFirmware)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(j))

	var outFirmware TypedFirmware
	if err := json.Unmarshal(j, &outFirmware); err != nil {
		t.Fatal(err)
	}

	if outFirmware.Type != "*uefi.Section" {
		t.Errorf("got %q, expected *uefi.Section", outFirmware.Type)
	}
	outSection, ok := outFirmware.Value.(*Section)
	if !ok {
		t.Fatalf("got %T; expected *uefi.Section", outFirmware.Value)
	}
	if outSection.Name != "CHARLIE" {
		t.Errorf("got %q, expected CHARLIE", outSection.Name)
	}
}

var (
	// Checksum Tests
	emptyBuf  = []byte{}
	sampleBuf = []byte{1, 2, 3, 4}
	overBuf   = []byte{0x1, 0x2, 0xFF, 0xFF}
	zeroBuf   = []byte{0, 0, 0, 0}
	threeBuf  = []byte{3, 3, 3}
)

func TestChecksum8(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		res  uint8
	}{
		{"emptyBuf", emptyBuf, 0},
		{"sampleBuf", sampleBuf, 10},
		{"overBuf", overBuf, 0x1},
		{"zeroBuf", zeroBuf, 0},
		{"threeBuf", threeBuf, 9},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if res := Checksum8(test.buf); res != test.res {
				t.Errorf("Checksum8 wrong result!, input was %#x, wanted \n%#x\n, got \n%#x\n", test.buf, test.res, res)
			}
		})
	}
}

func TestChecksum16(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		res  uint16
		msg  string
	}{
		{"emptyBuf", emptyBuf, 0, ""},
		{"sampleBuf", sampleBuf, 0x604, ""},
		{"overBuf", overBuf, 0x200, ""},
		{"zeroBuf", zeroBuf, 0, ""},
		{"threeBuf", threeBuf, 0, fmt.Sprintf("byte slice does not have even length, not able to do 16 bit checksum. Length was %v",
			len(threeBuf))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := Checksum16(test.buf)
			if res != test.res {
				t.Errorf("Checksum16 wrong result!, input was %#x, wanted \n%#x\n, got \n%#x\n", test.buf, test.res, res)
			}
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
		})
	}
}

func TestWrite3Size(t *testing.T) {
	var tests = []struct {
		name string
		val  uint64
		res  [3]byte
	}{
		{"emptySize", 0x0, [3]byte{0, 0, 0}},
		{"sampleSize", 0xABCDEF, [3]byte{0xEF, 0xCD, 0xAB}},
		{"max3ByteSize", 0xFFFFFF, [3]byte{0xFF, 0xFF, 0xFF}},
		{"over3ByteSize", 0x1000000, [3]byte{0xFF, 0xFF, 0xFF}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if res := Write3Size(test.val); res != test.res {
				t.Errorf("Write3Size wrong result!, input was %#x, wanted \n%#x\n, got \n%#x\n", test.val, test.res, res)
			}
		})
	}
}

func TestRead3Size(t *testing.T) {
	var tests = []struct {
		name string
		val  uint64
		arr  [3]byte
	}{
		{"emptySize", 0x0, [3]byte{0, 0, 0}},
		{"sampleSize", 0xABCDEF, [3]byte{0xEF, 0xCD, 0xAB}},
		{"max3ByteSize", 0xFFFFFF, [3]byte{0xFF, 0xFF, 0xFF}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if val := Read3Size(test.arr); val != test.val {
				t.Errorf("Read3Size wrong result!, input was %#x, wanted \n%#x\n, got \n%#x\n", test.arr, test.val, val)
			}
		})
	}
}

func TestAlign4(t *testing.T) {
	var tests = []struct {
		val uint64
		res uint64
	}{
		{0x4, 0x4},
		{0x5, 0x8},
	}
	for _, test := range tests {
		if res := Align4(test.val); res != test.res {
			t.Errorf("Align4 wrong result!, input was %#x, wanted \n%#x\n, got \n%#x\n", test.val, test.res, res)
		}
	}
}

func TestAlign8(t *testing.T) {
	var tests = []struct {
		val uint64
		res uint64
	}{
		{0x4, 0x8},
		{0x5, 0x8},
		{0x8, 0x8},
		{0x9, 0x10},
	}
	for _, test := range tests {
		if res := Align8(test.val); res != test.res {
			t.Errorf("Align8 wrong result!, input was %#x, wanted \n%#x\n, got \n%#x\n", test.val, test.res, res)
		}
	}
}
