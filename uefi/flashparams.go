package uefi

import (
	"fmt"
)

const (
	// FlashParamsSize is the size of a FlashParams struct
	FlashParamsSize = 4
)

// FlashFrequency is the type used for Frequency fields
type FlashFrequency uint

// Flash frequency constants
const (
	Freq20MHz      FlashFrequency = 0
	Freq33MHz      FlashFrequency = 1
	Freq48MHz      FlashFrequency = 2
	Freq50MHz30MHz FlashFrequency = 4
	Freq17MHz      FlashFrequency = 6
)

// FlashFrequencyStringMap maps frequency constants to strings
var FlashFrequencyStringMap = map[FlashFrequency]string{
	Freq20MHz:      "20MHz",
	Freq33MHz:      "33MHz",
	Freq48MHz:      "48MHz",
	Freq50MHz30MHz: "50Mhz30MHz",
	Freq17MHz:      "17MHz",
}

// FlashParams is a 4-byte object that holds the flash parameters information.
type FlashParams []byte

// FirstChipDensity returns the size of the first chip.
func (p FlashParams) FirstChipDensity() uint {
	return uint(p[0] & 0x0f)
}

// SecondChipDensity returns the size of the second chip.
func (p FlashParams) SecondChipDensity() uint {
	return uint((p[0] >> 4) & 0x0f)
}

// ReadClockFrequency returns the chip frequency while reading from the flash.
func (p FlashParams) ReadClockFrequency() FlashFrequency {
	return FlashFrequency((p[2] >> 1) & 0x07)
}

// FastReadEnabled returns if FastRead is enabled.
func (p FlashParams) FastReadEnabled() uint {
	return uint((p[2] >> 4) & 0x01)
}

// FastReadFrequency returns the frequency under FastRead.
func (p FlashParams) FastReadFrequency() FlashFrequency {
	return FlashFrequency((p[2] >> 5) & 0x07)
}

// FlashWriteFrequency returns the chip frequency for writing.
func (p FlashParams) FlashWriteFrequency() FlashFrequency {
	return FlashFrequency(p[3] & 0x07)
}

// FlashReadStatusFrequency returns the chip frequency while reading the flash status.
func (p FlashParams) FlashReadStatusFrequency() FlashFrequency {
	return FlashFrequency((p[3] >> 3) & 0x07)
}

// DualOutputFastReadSupported returns if Dual Output Fast Read is supported.
func (p FlashParams) DualOutputFastReadSupported() uint {
	return uint(p[3] >> 7)
}

func (p FlashParams) String() string {
	return fmt.Sprintf("FlashParams{...}")
}

// Summary prints a multi-line description of the FlashParams
func (p FlashParams) Summary() string {
	rcf, ok := FlashFrequencyStringMap[p.ReadClockFrequency()]
	if !ok {
		rcf = fmt.Sprintf("Unknown (%v)", p.ReadClockFrequency())
	}
	frf, ok := FlashFrequencyStringMap[p.FastReadFrequency()]
	if !ok {
		frf = fmt.Sprintf("Unknown (%v)", p.FastReadFrequency())
	}
	fwf, ok := FlashFrequencyStringMap[p.FlashWriteFrequency()]
	if !ok {
		fwf = fmt.Sprintf("Unknown (%v)", p.FlashWriteFrequency())
	}
	frsf, ok := FlashFrequencyStringMap[p.FlashReadStatusFrequency()]
	if !ok {
		frsf = fmt.Sprintf("Unknown (%v)", p.FlashReadStatusFrequency())
	}
	return fmt.Sprintf("FlashParams{\n"+
		"    FirstChipDensity=%v\n"+
		"    SecondChipDensity=%v\n"+
		"    ReadClockFrequency=%v\n"+
		"    FastReadEnabled=%v\n"+
		"    FastReadFrequency=%v\n"+
		"    FlashWriteFrequency=%v\n"+
		"    FlashReadStatusFrequency=%v\n"+
		"}",
		p.FirstChipDensity(),
		p.SecondChipDensity(),
		rcf,
		p.FastReadEnabled(),
		frf,
		fwf,
		frsf,
	)
}

// NewFlashParams initalizes a FlashParam struct from a slice of bytes
func NewFlashParams(buf []byte) (*FlashParams, error) {
	if len(buf) != FlashParamsSize {
		return nil, fmt.Errorf("Invalid image size: expected %v bytes, got %v",
			FlashParamsSize,
			len(buf),
		)
	}
	p := FlashParams(buf)
	return &p, nil
}
