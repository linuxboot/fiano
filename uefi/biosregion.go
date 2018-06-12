package uefi

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
