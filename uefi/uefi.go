package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Firmware is an interface to describe generic firmware types. The
// implementations (e.g. Flash image, or FirmwareVolume) must implement this
// interface.
type Firmware interface {
	Validate() []error
	Extract(dirpath string) error
	Assemble() ([]byte, error)
}

// Parse exposes a high-level parser for generic firmware types. It does not
// implement any parser itself, but it calls known parsers that implement the
// Firmware interface.
func Parse(buf []byte) (Firmware, error) {
	if _, err := FindSignature(buf); err == nil {
		// Intel rom.
		return NewFlashImage(buf)
	}
	// Non intel image such as edk2's OVMF
	// We don't know how to parse this header, so treat it as a large BIOSRegion
	return NewBIOSRegion(buf, nil)
}

// ExtractBinary simply dumps the binary to a specified directory and filename.
// It creates the directory if it doesn't already exist, and dumps the buffer to it.
// It returns the filepath of the binary, and an error if it exists.
// This is meant as a helper function for other Extract functions.
func ExtractBinary(buf []byte, dirPath string, filename string) (string, error) {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return "", err
	}

	// Dump the binary.
	fp := filepath.Join(dirPath, filename)
	if err := ioutil.WriteFile(fp, buf, 0666); err != nil {
		// Make sure we return "" since we don't want an invalid path to be serialized out.
		return "", err
	}
	return fp, nil
}

// Checksum8 does a 8 bit checksum of the slice passed in.
func Checksum8(buf []byte) uint8 {
	var sum uint8
	for _, val := range buf {
		sum += val
	}
	return sum
}

// Checksum16 does a 16 bit checksum of the byte slice passed in.
func Checksum16(buf []byte) (uint16, error) {
	r := bytes.NewReader(buf)
	buflen := len(buf)
	if buflen%2 != 0 {
		return 0, fmt.Errorf("byte slice does not have even length, not able to do 16 bit checksum. Length was %v",
			buflen)
	}
	var temp, sum uint16
	for i := 0; i < buflen; i += 2 {
		if err := binary.Read(r, binary.LittleEndian, &temp); err != nil {
			return 0, err
		}
		sum += temp
	}
	return sum, nil
}
