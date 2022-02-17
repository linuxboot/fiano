package psb

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/uefi"
	amd_manifest "github.com/linuxboot/fiano/pkg/amd/manifest"
)

// ParseAMDFirmware parses AMD firmware from the image bytes
func ParseAMDFirmware(image []byte) (*amd_manifest.AMDFirmware, error) {
	firmware, err := uefi.ParseUEFIFirmwareBytes(image)
	if err != nil {
		return nil, fmt.Errorf("could not parse firmware image: %w", err)
	}
	amdFw, err := amd_manifest.NewAMDFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD Firmware: %w", err)
	}
	return amdFw, nil
}

// ParseAMDFirmwareFile parses AMD firmware from the image file
func ParseAMDFirmwareFile(path string) (*amd_manifest.AMDFirmware, error) {
	firmware, err := uefi.ParseUEFIFirmwareFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not parse firmware image: %w", err)
	}
	amdFw, err := amd_manifest.NewAMDFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD Firmware: %w", err)
	}
	return amdFw, nil
}
