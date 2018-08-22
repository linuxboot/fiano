package uefi

import (
	"errors"
	"fmt"
	"io/ioutil"
)

// BIOSRegion represents the Bios Region in the firmware.
// It holds all the FVs as well as padding
// TODO(ganshun): handle padding
type BIOSRegion struct {
	// holds the raw data
	Buf             []byte `json:"-"`
	FirmwareVolumes []*FirmwareVolume

	//Metadata for extraction and recovery
	ExtractPath string
	// This is a pointer to the Region struct laid out in the ifd
	Position *Region `json:",omitempty"`
}

// NewBIOSRegion parses a sequence of bytes and returns a BIOSRegion
// object, if a valid one is passed, or an error. It also points to the
// Region struct uncovered in the ifd.
func NewBIOSRegion(buf []byte, r *Region) (*BIOSRegion, error) {
	br := BIOSRegion{Buf: buf, Position: r}
	var absOffset uint64
	for {
		offset := FindFirmwareVolumeOffset(buf)
		if offset < 0 {
			// no firmware volume found, stop searching
			break
		}
		absOffset += uint64(offset) // Find start of volume relative to bios region.
		fv, err := NewFirmwareVolume(buf[offset:], absOffset)
		if err != nil {
			return nil, err
		}
		absOffset += fv.Length
		buf = buf[uint64(offset)+fv.Length:]
		br.FirmwareVolumes = append(br.FirmwareVolumes, fv)
		// FIXME remove the `break` and move the offset to the next location to
		// search for FVs (i.e. offset + fv.size)
	}
	if len(br.FirmwareVolumes) > 0 {
		Attributes.ErasePolarity = br.FirmwareVolumes[0].GetErasePolarity()
	}
	return &br, nil
}

// Apply calls the visitor on the BIOSRegion.
func (br *BIOSRegion) Apply(v Visitor) error {
	return v.Visit(br)
}

// ApplyChildren calls the visitor on each child node of BIOSRegion.
func (br *BIOSRegion) ApplyChildren(v Visitor) error {
	for _, fv := range br.FirmwareVolumes {
		if err := fv.Apply(v); err != nil {
			return err
		}
	}
	return nil
}

// Validate Region
func (br *BIOSRegion) Validate() []error {
	// TODO: Add more verification if needed.
	errs := make([]error, 0)
	if br.Position != nil && !br.Position.Valid() {
		errs = append(errs, fmt.Errorf("BIOSRegion is not valid, region was %v", *br.Position))
	}
	if len(br.FirmwareVolumes) == 0 {
		errs = append(errs, errors.New("no firmware volumes in BIOS Region"))
	}

	for i, fv := range br.FirmwareVolumes {
		errs = append(errs, fv.Validate()...)
		if i == 0 {
			Attributes.ErasePolarity = br.FirmwareVolumes[i].GetErasePolarity()
		}
		// We have to do this because they didn't put an encapsulating structure around the FVs.
		// This means it's possible for different firmware volumes to report different erase polarities.
		// Now we have to check to see if we're in some insane state.
		if ep := fv.GetErasePolarity(); ep != Attributes.ErasePolarity {
			errs = append(errs, fmt.Errorf("erase polarity mismatch! fv 0 has %#x and fv %d has %#x",
				Attributes.ErasePolarity, i, ep))
		}
	}
	return errs
}

// Assemble assembles the Bios Region from the binary file.
func (br *BIOSRegion) Assemble() ([]byte, error) {
	var err error
	br.Buf, err = ioutil.ReadFile(br.ExtractPath)
	if err != nil {
		return nil, err
	}

	// Assemble the Firmware Volumes
	for i, fv := range br.FirmwareVolumes {
		// We have to trust the JSON's polarity
		if i == 0 {
			Attributes.ErasePolarity = fv.GetErasePolarity()
		}
		buf, err := fv.Assemble()
		if err != nil {
			return nil, err
		}
		// copy the fv over the original
		// TODO: handle different sizes.
		// We'll have to FF out the new regions/ check for clashes
		copy(br.Buf[fv.FVOffset:fv.FVOffset+fv.Length], buf)
	}

	return br.Buf, nil
}
