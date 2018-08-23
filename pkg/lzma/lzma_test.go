package lzma

import (
	"io/ioutil"
	"reflect"
	"testing"
)

var tests = []struct {
	name            string
	encodedFilename string
	decodedFilename string
	encode          func([]byte) ([]byte, error)
	decode          func([]byte) ([]byte, error)
}{
	{
		name:            "random data",
		encodedFilename: "testdata/random.bin.lzma",
		decodedFilename: "testdata/random.bin",
		encode:          Encode,
		decode:          Decode,
	},
	{
		name:            "random data x86",
		encodedFilename: "testdata/random.bin.lzma86",
		decodedFilename: "testdata/random.bin",
		encode:          EncodeX86,
		decode:          DecodeX86,
	},
}

func TestEncodeDecode(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Read test data.
			want, err := ioutil.ReadFile(tt.decodedFilename)
			if err != nil {
				t.Fatal(err)
			}

			// Encoded and decode
			encoded, err := tt.encode(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tt.decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
			}
		})
	}
}

func TestDecode(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Read test data.
			want, err := ioutil.ReadFile(tt.decodedFilename)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := ioutil.ReadFile(tt.encodedFilename)
			if err != nil {
				t.Fatal(err)
			}

			// Decode
			got, err := tt.decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
			}
		})
	}
}
