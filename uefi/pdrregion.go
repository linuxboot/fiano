package uefi

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
