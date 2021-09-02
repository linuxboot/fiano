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

// KeyDatabase represents a key database structure as parsed from firmware
type KeyDatabase struct {
	header *PSPHeader
}

// Header returns a pointer to the internal header structure
func (kdb *KeyDatabase) Header() *PSPHeader {
	return kdb.header
}

// extractKeyDatabase extracts the key database structure from firmware image
func extractKeyDatabase(pspFw *amd_manifest.PSPFirmware, firmware amd_manifest.Firmware) (*KeyDatabase, error) {

	if pspFw == nil {
		return nil, fmt.Errorf("cannot extract key database from nil PSP Firmware")
	}

	if pspFw.PSPDirectoryLevel1 == nil {
		return nil, fmt.Errorf("cannot extract key database without PSP Directory Level 1")
	}

	for _, entry := range pspFw.PSPDirectoryLevel1.Entries {
		if entry.Type == KeyDatabaseEntry {
			firmwareBytes := firmware.ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract key database from firmware image, boundary check fail: %w", err)
			}
			header, err := NewPSPHeader(firmwareBytes[start:end])
			if err != nil {
				return nil, fmt.Errorf("could not construct PSP header from key database: %w", err)
			}
			return &KeyDatabase{header: header}, nil
		}
	}

	return nil, fmt.Errorf("could not find KeyDatabaseEntry (%d) in PSP Directory Level 1", KeyDatabaseEntry)
}

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

	keyDB, err := extractKeyDatabase(pspFw, firmware)
	if err != nil {
		return fmt.Errorf("could not extract key database: %w", err)
	}

	header := keyDB.Header()
	if header == nil {
		return fmt.Errorf("unexpected nil header for keydb")
	}

	signature, signedData, err := header.GetSignature()
	if err != nil {
		return fmt.Errorf("could not extract signature information from PSP Header: %w", err)
	}

	fmt.Println("=== KeyDB header signature information ===")
	fmt.Println(signature.String())
	if err := signature.Validate(signedData, amdPk); err != nil {
		return fmt.Errorf("could not validate KeyDB PSP Header signature with AMD Public key: %w", err)
	}
	return nil
}
