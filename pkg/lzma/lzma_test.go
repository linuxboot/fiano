// Copyright 2018 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

import (
	"io/ioutil"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	// Read test data.
	want, err := ioutil.ReadFile("testdata/data.bin")
	if err != nil {
		t.Fatal(err)
	}

	// Encoded and decode
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
	}
}

func TestDecode(t *testing.T) {
	// Read test data.
	want, err := ioutil.ReadFile("testdata/data.bin")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ioutil.ReadFile("testdata/data.bin.lzma")
	if err != nil {
		t.Fatal(err)
	}

	// Decode
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
	}
}
