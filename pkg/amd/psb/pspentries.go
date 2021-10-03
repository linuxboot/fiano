package psb

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

const (
	// AMDPublicKeyEntry denotes AMD public key entry in PSP Directory table
	AMDPublicKeyEntry amd_manifest.PSPDirectoryTableEntryType = 0x00

	// KeyDatabaseEntry points to region of firmware containing key database
	KeyDatabaseEntry amd_manifest.PSPDirectoryTableEntryType = 0x50

	// ABLPublicKey represents the key used to sign ABL firmware
	ABLPublicKey amd_manifest.PSPDirectoryTableEntryType = 0x0A

	// OEMSigningKeyEntry represents the OEM signing key
	OEMSigningKeyEntry amd_manifest.BIOSDirectoryTableEntryType = 0x05

	// BIOSRTMVolumeEntry represents the RTM volume
	BIOSRTMVolumeEntry amd_manifest.BIOSDirectoryTableEntryType = 0x62

	// BIOSRTMSignatureEntry represents the entry holding the RTM volume signature
	BIOSRTMSignatureEntry amd_manifest.BIOSDirectoryTableEntryType = 0x07
)

// extractRawPSPEntry extracts data corresponding to an entry in the PSP table. We assume
// to look-up for the entry in the level 1 directory.
func extractRawPSPEntry(id amd_manifest.PSPDirectoryTableEntryType, pspFw *amd_manifest.PSPFirmware, firmware amd_manifest.Firmware) ([]byte, error) {

	if pspFw.PSPDirectoryLevel1 == nil {
		return nil, fmt.Errorf("cannot extract raw PSP entry without PSP Directory Level 1")
	}

	// TODO: add support for Level 2 directory
	for _, entry := range pspFw.PSPDirectoryLevel1.Entries {
		if entry.Type == id {
			firmwareBytes := firmware.ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract PSP entry %x from firmware image, boundary check fail: %w", id, err)
			}
			return firmwareBytes[start:end], nil
		}
	}
	return nil, fmt.Errorf("could not find PSP entry %x in PSP Directory Level 1", id)
}

// ValidatePSPEntries validates signature of PSP entries given their entry values in PSP Table
func ValidatePSPEntries(firmware amd_manifest.Firmware, entries []string) ([]SignatureValidationResult, error) {

	keyDB, err := GetKeys(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not extract key database: %w", err)
	}

	amdFw, err := amd_manifest.NewAMDFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not parse AMD Firmware: %w", err)
	}

	pspFw := amdFw.PSPFirmware()

	validationResults := make([]SignatureValidationResult, 0, len(entries))

	for _, entry := range entries {
		id, err := strconv.ParseInt(entry, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse hexadecimal entry: %w", err)
		}

		data, err := extractRawPSPEntry(amd_manifest.PSPDirectoryTableEntryType(id), pspFw, firmware)
		if err != nil {
			return nil, fmt.Errorf("could not extract entry 0x%x from PSP table: %w", id, err)
		}
		binary, err := newPSPBinary(data)
		if err != nil {
			return nil, fmt.Errorf("could not create PSB binary from raw data for entry 0x%x: %w", entry, err)
		}
		signedBlob, err := binary.getSignedBlob(keyDB)
		var signedElement strings.Builder
		fmt.Fprintf(&signedElement, "PSP entry 0x%s", entry)

		if err != nil {
			var sigError *SignatureCheckError
			if errors.As(err, &sigError) {
				validationResults = append(validationResults, SignatureValidationResult{signedElement: signedElement.String(), signingKey: sigError.SigningKey(), err: err})
			} else {
				validationResults = append(validationResults, SignatureValidationResult{signedElement: signedElement.String(), err: err})
			}
		} else {
			signature := signedBlob.Signature()
			validationResults = append(validationResults, SignatureValidationResult{signedElement: signedElement.String(), signingKey: signature.SigningKey(), err: err})
		}

	}

	return validationResults, nil
}
