package uefi

import (
	"fmt"
	"path/filepath"
)

// BIOSRegion represents the Bios Region in the firmware.
// It holds all the FVs as well as padding
// TODO(ganshun): handle padding
type BIOSRegion struct {
	// holds the raw data
	buf             []byte
	FirmwareVolumes []FirmwareVolume

	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region
}

// NewBIOSRegion parses a sequence of bytes and returns a BIOSRegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewBIOSRegion(buf []byte, r *Region) (*BIOSRegion, error) {
	br := BIOSRegion{buf: buf, Position: r}
	for {
		offset := FindFirmwareVolumeOffset(buf)
		if offset == -1 {
			// no firmware volume found, stop searching
			break
		}
		fv, err := NewFirmwareVolume(buf[offset:])
		if err != nil {
			return nil, err
		}
		buf = buf[uint64(offset)+fv.Length:]
		br.FirmwareVolumes = append(br.FirmwareVolumes, *fv)
		// FIXME remove the `break` and move the offset to the next location to
		// search for FVs (i.e. offset + fv.size)
	}
	return &br, nil
}

// Validate Region
func (br *BIOSRegion) Validate() []error {
	// TODO: Add more verification if needed.
	errs := make([]error, 0)
	if br.Position == nil {
		errs = append(errs, fmt.Errorf("BIOSRegion position is nil"))
	}
	if !br.Position.Valid() {
		errs = append(errs, fmt.Errorf("BIOSRegion is not valid, region was %v", br.Position))
	}
	if len(br.FirmwareVolumes) == 0 {
		errs = append(errs, fmt.Errorf("no firmware volumes in BIOS Region"))
	}
	return errs
}

// Extract extracts the Bios Region to the directory passed in.
func (br *BIOSRegion) Extract(parentPath string) error {
	// We just dump the binary for now
	var err error
	dirPath := filepath.Join(parentPath, "bios")
	br.ExtractPath, err = ExtractBinary(br.buf, dirPath, "biosregion.bin")
	return err
}
