package uefi

import (
	"errors"
	"fmt"
	"path/filepath"
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

// Validate Region
func (me *MERegion) Validate() []error {
	// TODO: Add more verification if needed.
	errs := make([]error, 0)
	if me.Position == nil {
		errs = append(errs, errors.New("MERegion position is nil"))
	}
	if !me.Position.Valid() {
		errs = append(errs, fmt.Errorf("MERegion is not valid, region was %v", *me.Position))
	}
	return errs
}

// Extract extracts the ME region to the directory passed in.
func (me *MERegion) Extract(parentPath string) error {
	var err error
	dirPath := filepath.Join(parentPath, "me")
	// We just dump the binary for now
	me.ExtractPath, err = ExtractBinary(me.buf, dirPath, "meregion.bin")
	return err
}
