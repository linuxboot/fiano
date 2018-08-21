package lzma

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	// Read test data.
	want, err := ioutil.ReadFile("testdata/data.bin")
	if err != nil {
		t.Fatal(err)
	}

	// Encode and decode.
	encoded, err := Default.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Default.Decode(encoded)
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

	// Decode.
	got, err := Default.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decompressed image did not match, (got: %d bytes, want: %d bytes)", len(got), len(want))
	}
}

func TestNonStreamed(t *testing.T) {
	// Read test data.
	decoded, err := ioutil.ReadFile("testdata/data.bin")
	if err != nil {
		t.Fatal(err)
	}

	// Encode.
	encoded, err := Default.Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}

	// Write enconded data to a temporary file.
	tmpFile, err := ioutil.TempFile("", "fiano-test")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Use "file" to get information from the header.
	got, err := exec.Command("file", tmpFile.Name()).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s: LZMA compressed data, non-streamed, size %d\n", tmpFile.Name(), len(decoded))
	if want != string(got) {
		t.Fatalf("want %q, got %q", want, string(got))
	}
}
