package psb

import (
	"fmt"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry amd_manifest.PSPDirectoryTableEntryType = 0x00
)

// GetKeyDB extracts the key database from firmware image
func GetKeyDB(firmware amd_manifest.Firmware) error {
	pspFw, err := amd_manifest.ParsePSPFirmware(firmware)
	if err != nil {
		return fmt.Errorf("could not get key database: %w", err)
	}

	key, err := extractAMDPublicKey(pspFw, firmware)
	if err != nil {
		return fmt.Errorf("could no extract AMD public key from firmware: %w", err)
	}
	fmt.Println(key.String())
	return nil
}
