package uefi

import (
	"fmt"
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

// Validate Region
func (gbe *GBERegion) Validate() []error {
	// TODO: Add more verification if needed.
	errs := make([]error, 0)
	if gbe.Position == nil {
		errs = append(errs, fmt.Errorf("GBERegion position is nil"))
	}
	if !gbe.Position.Valid() {
		errs = append(errs, fmt.Errorf("GBERegion is not valid, region was %v", gbe.Position))
	}
	return errs
}

// Extract extracts the GBE region to the directory passed in.
func (gbe *GBERegion) Extract(dirPath string) error {
	var err error
	// We just dump the binary for now
	gbe.ExtractPath, err = ExtractBinary(gbe.buf, dirPath, "gberegion.bin")
	return err
}
