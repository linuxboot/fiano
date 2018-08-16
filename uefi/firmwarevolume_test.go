package uefi

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var (
	// FV examples
	emptyFV  = []byte{} // Empty file
	sampleFV []byte     // Sample FV from OVMF
)

func init() {
	var err error
	sampleFV, err = ioutil.ReadFile("../integration/roms/ovmfSECFV.fv")
	if err != nil {
		log.Fatal(err)
	}
}

func TestValidateFV(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msgs []string
	}{
		{"sampleFV", sampleFV, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fv, err := NewFirmwareVolume(test.buf, 0)
			if err != nil {
				t.Fatalf("Error was not expected, got %v", err.Error())
			}
			errs := fv.Validate()
			if len(errs) != len(test.msgs) {
				t.Errorf("Errors mismatched, wanted \n%v\n, got \n%v\n", test.msgs, errs)
			} else {
				for i := range errs {
					if errs[i].Error() != test.msgs[i] {
						t.Errorf("Error mismatched, wanted \n%v\n, got \n%v\n", test.msgs[i], errs[i].Error())
					}
				}
			}
		})
	}
}

func TestExtractAssembleFV(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "fv-test")
	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}

	defer os.RemoveAll(tmpDir)
	var tests = []struct {
		name    string
		origBuf []byte
		newBuf  []byte
	}{
		{"sampleFV", sampleFV, sampleFV},
	}
	// Set erasepolarity to FF
	Attributes.ErasePolarity = 0xFF
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fv, err := NewFirmwareVolume(test.origBuf, 0)
			if err != nil {
				t.Fatalf("Unable to parse file object %v, got %v", test.origBuf, err.Error())
			}
			if err = fv.Extract(tmpDir); err != nil {
				t.Fatalf("Unable to extract file %v, got %v", test.origBuf, err.Error())
			}
			nb, err := fv.Assemble()
			if len(test.newBuf) != len(nb) {
				t.Fatalf("Binaries differ! expected \n%v\n assembled \n%v\n", test.newBuf, nb)
			}
			for i := range test.newBuf {
				if test.newBuf[i] != nb[i] {
					t.Fatalf("Binaries differ! expected \n%v\n assembled \n%v\n", test.newBuf, nb)
				}
			}
		})
	}
}

func TestNewFirmwareVolume(t *testing.T) {
	var tests = []struct {
		name string
		buf  []byte
		msg  string
	}{
		{"emptyFV", emptyFV, fmt.Sprintf("Firmware Volume size too small: expected %d bytes, got %d",
			FirmwareVolumeMinSize, len(emptyFV))},
		{"sampleFV", sampleFV, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewFirmwareVolume(test.buf, 0)
			if err == nil && test.msg != "" {
				t.Errorf("Error was not returned, expected %v", test.msg)
			} else if err != nil && err.Error() != test.msg {
				t.Errorf("Mismatched Error returned, expected \n%v\n got \n%v\n", test.msg, err.Error())
			}
		})
	}
}
