package psb

import (
	"fmt"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry amd_manifest.PSPDirectoryTableEntryType = 0x00

	// KeyDatabaseEntry points to region of firmware containing key database
	KeyDatabaseEntry amd_manifest.PSPDirectoryTableEntryType = 0x50
)

// GetKeyDB extracts the key database from firmware image
func GetKeyDB(firmware amd_manifest.Firmware) error {
	pspFw, err := amd_manifest.ParsePSPFirmware(firmware)
	if err != nil {
		return fmt.Errorf("could not get key database: %w", err)
	}

	amdPk, err := extractAMDPublicKey(pspFw, firmware)
	if err != nil {
		return fmt.Errorf("could no extract AMD public key from firmware: %w", err)
	}

	keyDBBinary, err := ExtractPSPBinary(KeyDatabaseEntry, pspFw, firmware)
	if err != nil {
		return fmt.Errorf("could not extract KeyDatabaseEntry entry (%d) from PSP firmware: %w", KeyDatabaseEntry, err)
	}

	signature, signedData, err := keyDBBinary.GetSignature()
	if err != nil {
		return fmt.Errorf("could not extract signature information from keydb binary: %w", err)
	}

	fmt.Println("=== KeyDB signature information ===")
	fmt.Println(signature.String())
	if err := signature.Validate(signedData, amdPk); err != nil {
		return fmt.Errorf("could not validate KeyDB PSP Header signature with AMD Public key: %w", err)
	}
	return nil
}
