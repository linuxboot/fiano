package uefi

import (
	"os"
)

// GBERegion represents the GBE Region in the firmware.
type GBERegion struct {
	// holds the raw data
	buf []byte
	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region
}

// NewGBERegion parses a sequence of bytes and returns a GBERegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewGBERegion(buf []byte, r *Region) (*GBERegion, error) {
	gbe := GBERegion{buf: buf, Position: r}
	return &gbe, nil
}

// Extract extracts the GBE region to the directory passed in.
func (gbe *GBERegion) Extract(dirPath string) error {
	// Create the directory if it doesn't exist
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}

	// Dump the binary.
	gbe.ExtractPath = dirPath + "/gberegion.bin"
	binFile, err := os.OpenFile(gbe.ExtractPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer binFile.Close()
	_, err = binFile.Write(gbe.buf)
	if err != nil {
		return err
	}
	return nil
}
