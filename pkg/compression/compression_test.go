// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package compression

import (
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/linuxboot/fiano/pkg/guid"
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

func TestCompressorFromGUID(t *testing.T) {
	var compressors = []struct {
		name            string
		guid            *guid.GUID
		expected        Compressor
		encodedFilename string
		decodedFilename string
	}{
		{
			name:            "system xz",
			guid:            &LZMAGUID,
			expected:        &SystemLZMA{"xz"},
			encodedFilename: "testdata/random.bin.lzma",
			decodedFilename: "testdata/random.bin",
		},
		{
			name:            "lzma",
			guid:            &LZMAX86GUID,
			expected:        &LZMAX86{&SystemLZMA{"xz"}},
			encodedFilename: "testdata/random.bin.lzma86",
			decodedFilename: "testdata/random.bin",
		},
	}
	for _, tt := range compressors {
		t.Run(tt.name, func(t *testing.T) {
			compressor := CompressorFromGUID(tt.guid)
			if compressor.Name() != tt.expected.Name() {
				t.Fatalf("compressor from guid %v did not match (got: %s, want: %s)", tt.guid, compressor.Name(), tt.expected.Name())
			}
			// Read test data.
			want, err := ioutil.ReadFile(tt.decodedFilename)
			if err != nil {
				t.Fatal(err)
			}
			// Compare encodings
			encoded, err := compressor.Encode(want)
			if err != nil {
				t.Fatal(err)
			}
			expectedEncoded, terr := tt.expected.Encode(want)
			if terr != nil {
				t.Fatal(terr)
			}
			if !reflect.DeepEqual(encoded, expectedEncoded) {
				t.Fatalf("compressor from guid %v encoding did not match (got: %s, want: %s)", tt.guid, encoded, expectedEncoded)
			}
			// Compare decodings
			got, err := compressor.Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			expectedGot, terr := tt.expected.Decode(encoded)
			if terr != nil {
				t.Fatal(terr)
			}
			if !reflect.DeepEqual(got, expectedGot) {
				t.Fatalf("compressor from guid %v decoding did not match (got: %s, want: %s)", tt.guid, got, expectedGot)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
			}
		})

	}
}
