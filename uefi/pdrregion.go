package uefi

import (
	"os"
)

// PDRRegion represents the PDR Region in the firmware.
type PDRRegion struct {
	// holds the raw data
	buf []byte
	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region
}

// NewPDRRegion parses a sequence of bytes and returns a PDRRegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewPDRRegion(buf []byte, r *Region) (*PDRRegion, error) {
	pdr := PDRRegion{buf: buf, Position: r}
	return &pdr, nil
}

// Extract extracts the PDR region to the directory passed in.
func (pdr *PDRRegion) Extract(dirPath string) error {
	// Create the directory if it doesn't exist
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}

	// Dump the binary.
	pdr.ExtractPath = dirPath + "/pdrregion.bin"
	binFile, err := os.OpenFile(pdr.ExtractPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer binFile.Close()
	_, err = binFile.Write(pdr.buf)
	if err != nil {
		return err
	}
	return nil
}
