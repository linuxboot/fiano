package uefi

import (
	"fmt"
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

// Validate Region
func (pd *PDRegion) Validate() []error {
	// TODO: Add more verification if needed.
	errs := make([]error, 0)
	if pd.Position == nil {
		errs = append(errs, fmt.Errorf("PDRegion position is nil"))
	}
	if !pd.Position.Valid() {
		errs = append(errs, fmt.Errorf("PDRegion is not valid, region was %v", pd.Position))
	}
	return errs
}

// Extract extracts the PDR region to the directory passed in.
func (pd *PDRegion) Extract(dirPath string) error {
	var err error
	// We just dump the binary for now
	pd.ExtractPath, err = ExtractBinary(pd.buf, dirPath, "pdregion.bin")
	return err
}
