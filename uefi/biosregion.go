package uefi

import (
	"fmt"
	"strings"
)

// BiosRegion represents the Bios Region in the firmware.
// It holds all the FVs as well as padding
// TODO(ganshun): handle padding
type BiosRegion struct {
	FirmwareVolumes []FirmwareVolume
}

// Summary prints a multi-line description of the Bios Region
func (br BiosRegion) Summary() string {
	var fvols []string
	for _, fv := range br.FirmwareVolumes {
		fvols = append(fvols, fv.Summary())
	}
	return fmt.Sprintf("BiosRegion{\n"+
		"    FirmwareVolumes=[\n"+
		"        %v\n"+
		"    ]\n"+
		"}", Indent(strings.Join(fvols, "\n"), 8))
}

// NewBiosRegion parses a sequence of bytes and returns a BiosRegion
// object, if a valid one is passed, or an error
func NewBiosRegion(data []byte) (*BiosRegion, error) {
	var br BiosRegion
	for {
		offset := FindFirmwareVolumeOffset(data)
		if offset == -1 {
			// no firmware volume found, stop searching
			break
		}
		fv, err := NewFirmwareVolume(data[offset:])
		if err != nil {
			return nil, err
		}
		data = data[uint64(offset)+fv.Length:]
		br.FirmwareVolumes = append(br.FirmwareVolumes, *fv)
		// FIXME remove the `break` and move the offset to the next location to
		// search for FVs (i.e. offset + fv.size)
	}
	return &br, nil
}
