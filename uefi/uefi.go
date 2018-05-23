package uefi

import (
	"bytes"
	"fmt"
)

// Firmware is an interface to describe generic firmware types. The
// implementations (e.g. Flash image, or FirmwareVolume) must implement this
// interface.
type Firmware interface {
	Validate() []error
	Summary() string
}

// Parse exposes a high-level parser for generic firmware types. It does not
// implement any parser itself, but it calls known parsers that implement the
// Firmware interface.
func Parse(buf []byte) (Firmware, error) {
	switch {
	case len(buf) >= 20 && bytes.Equal(buf[16:16+len(FlashSignature)], FlashSignature):
		return NewFlashImage(buf)
	case bytes.Equal(buf[:len(FlashSignature)], FlashSignature):
		return NewFlashImage(buf)
	default:
		return nil, fmt.Errorf("Unknown firmware type")
	}
}
