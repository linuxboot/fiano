// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compression

import (
	"io/ioutil"
	"reflect"
	"testing"
)

var tests = []struct {
	name            string
	encodedFilename string
	decodedFilename string
	compressor      Compressor
}{
	{
		name:            "random data LZMA",
		encodedFilename: "testdata/random.bin.lzma",
		decodedFilename: "testdata/random.bin",
		compressor:      &LZMA{},
	},
	{
		name:            "random data SystemLZMA",
		encodedFilename: "testdata/random.bin.lzma",
		decodedFilename: "testdata/random.bin",
		compressor:      &SystemLZMA{"xz"},
	},
	{
		name:            "random data LZMAX86",
		encodedFilename: "testdata/random.bin.lzma86",
		decodedFilename: "testdata/random.bin",
		compressor:      &LZMAX86{&LZMA{}},
	},
	{
		name:            "random data SystemLZMAX86",
		encodedFilename: "testdata/random.bin.lzma86",
		decodedFilename: "testdata/random.bin",
		compressor:      &LZMAX86{&SystemLZMA{"xz"}},
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
			encoded, err := tt.compressor.Encode(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tt.compressor.Decode(encoded)
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
			got, err := tt.compressor.Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
			}
		})
	}
}
