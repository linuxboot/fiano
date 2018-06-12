package uefi

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Firmware is an interface to describe generic firmware types. The
// implementations (e.g. Flash image, or FirmwareVolume) must implement this
// interface.
type Firmware interface {
	Validate() []error
	Extract(dirpath string) error
}

// Parse exposes a high-level parser for generic firmware types. It does not
// implement any parser itself, but it calls known parsers that implement the
// Firmware interface.
func Parse(buf []byte) (Firmware, error) {
	switch {
	case len(buf) >= 20 && bytes.Equal(buf[16:16+len(FlashSignature)], FlashSignature):
		return NewFlashImage(buf)
	case bytes.Equal(buf[:len(FlashSignature)], FlashSignature):
		return NewFlashImage(buf)
	default:
		return nil, fmt.Errorf("Unknown firmware type")
	}
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
	binFile, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return fp, err
	}
	defer binFile.Close()
	_, err = binFile.Write(buf)
	return fp, err
}
