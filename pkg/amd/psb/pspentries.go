package psb

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	amd_manifest "github.com/9elements/converged-security-suite/pkg/amd/manifest"
)

// extractRawPSPEntry extracts data corresponding to an entry in the PSP table. We assume
// to look-up for the entry in the level 1 directory.
func extractRawPSPEntry(id amd_manifest.PSPDirectoryTableEntryType, pspFw *amd_manifest.PSPFirmware, firmware amd_manifest.Firmware) ([]byte, error) {

	if pspFw.PSPDirectoryLevel1 == nil {
		return nil, fmt.Errorf("cannot extract key database without PSP Directory Level 1")
	}

	// TODO: add support for Level 2 directory
	for _, entry := range pspFw.PSPDirectoryLevel1.Entries {
		if entry.Type == id {
			firmwareBytes := firmware.ImageBytes()
			start := entry.LocationOrValue
			end := start + uint64(entry.Size)
			if err := checkBoundaries(start, end, firmwareBytes); err != nil {
				return nil, fmt.Errorf("cannot extract key database from firmware image, boundary check fail: %w", err)
			}
			return firmwareBytes[start:end], nil
		}
	}
	return nil, fmt.Errorf("could not find PSP entry %d in PSP Directory Level 1", id)
}

// ValidatePSPEntries validates signature of PSP entries given their entry values in PSP Table
func ValidatePSPEntries(firmware amd_manifest.Firmware, entries []string) ([]SignatureValidationResult, error) {

	keyDB, err := GetKeyDB(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not extract key database: %w", err)
	}

	pspFw, err := amd_manifest.ParsePSPFirmware(firmware)
	if err != nil {
		return nil, fmt.Errorf("could not get key database: %w", err)
	}

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
