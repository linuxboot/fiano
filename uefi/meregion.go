package uefi

import (
	"os"
)

// MERegion represents the ME Region in the firmware.
type MERegion struct {
	// holds the raw data
	buf []byte
	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region
}

// NewMERegion parses a sequence of bytes and returns a MERegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewMERegion(buf []byte, r *Region) (*MERegion, error) {
	me := MERegion{buf: buf, Position: r}
	return &me, nil
}

// Extract extracts the ME region to the directory passed in.
func (me *MERegion) Extract(dirPath string) error {
	// Create the directory if it doesn't exist
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}

	// Dump the binary.
	me.ExtractPath = dirPath + "/meregion.bin"
	binFile, err := os.OpenFile(me.ExtractPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer binFile.Close()
	_, err = binFile.Write(me.buf)
	if err != nil {
		return err
	}
	return nil
}
