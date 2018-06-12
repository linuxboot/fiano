package uefi

import (
	"os"
)

// PDRegion represents the PD Region in the firmware.
type PDRegion struct {
	// holds the raw data
	buf []byte
	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region
}

// NewPDRegion parses a sequence of bytes and returns a PDRegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewPDRegion(buf []byte, r *Region) (*PDRegion, error) {
	pdr := PDRegion{buf: buf, Position: r}
	return &pdr, nil
}

// Extract extracts the PDR region to the directory passed in.
func (pd *PDRegion) Extract(dirPath string) error {
	// Create the directory if it doesn't exist
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}

	// Dump the binary.
	pd.ExtractPath = dirPath + "/pdregion.bin"
	binFile, err := os.OpenFile(pd.ExtractPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer binFile.Close()
	_, err = binFile.Write(pd.buf)
	if err != nil {
		return err
	}
	return nil
}
